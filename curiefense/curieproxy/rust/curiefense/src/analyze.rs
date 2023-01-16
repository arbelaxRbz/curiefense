use std::collections::HashSet;

use crate::acl::check_acl;
use crate::config::contentfilter::ContentFilterRules;
use crate::config::flow::FlowMap;
use crate::config::HSDB;
use crate::contentfilter::{content_filter_check, masking};
use crate::flow::{flow_build_query, flow_info, flow_process, flow_resolve_query, FlowCheck, FlowResult};
use crate::grasshopper::{challenge_phase01, challenge_phase02, check_app_sig, handle_bio_reports, Grasshopper, PrecisionLevel, GHMode};
use crate::interface::stats::{BStageMapped, StatsCollect};
use crate::interface::{
    merge_decisions, AclStage, AnalyzeResult, BDecision, BlockReason, Decision, Location, SimpleDecision, Tags,
};
use crate::limit::{limit_build_query, limit_info, limit_process, limit_resolve_query, LimitCheck, LimitResult};
use crate::logs::Logs;
use crate::redis::redis_async_conn;
use crate::utils::{eat_errors, BodyDecodingResult, RequestInfo};

pub enum CfRulesArg<'t> {
    Global,
    Get(Option<&'t ContentFilterRules>),
}

pub struct APhase0 {
    pub flows: FlowMap,
    pub globalfilter_dec: SimpleDecision,
    pub precision_level: PrecisionLevel,
    pub itags: Tags,
    pub reqinfo: RequestInfo,
    pub stats: StatsCollect<BStageMapped>,
}

#[derive(Clone)]
pub struct AnalysisInfo {
    precision_level: PrecisionLevel,
    p0_decision: Decision,
    reqinfo: RequestInfo,
    stats: StatsCollect<BStageMapped>,
    tags: Tags,
}

#[derive(Clone)]
pub struct AnalysisPhase<FLOW, LIMIT> {
    pub flows: Vec<FLOW>,
    pub limits: Vec<LIMIT>,
    info: AnalysisInfo,
}

impl<FLOW, LIMIT> AnalysisPhase<FLOW, LIMIT> {
    pub fn next<NFLOW, NLIMIT>(self, flows: Vec<NFLOW>, limits: Vec<NLIMIT>) -> AnalysisPhase<NFLOW, NLIMIT> {
        AnalysisPhase {
            flows,
            info: self.info,
            limits,
        }
    }
    pub fn new(flows: Vec<FLOW>, limits: Vec<LIMIT>, info: AnalysisInfo) -> Self {
        Self { flows, info, limits }
    }
}

pub type APhase1 = AnalysisPhase<FlowCheck, LimitCheck>;

pub enum InitResult {
    Res(AnalyzeResult),
    Phase1(APhase1),
}

#[allow(clippy::too_many_arguments)]
pub fn analyze_init<GH: Grasshopper>(logs: &mut Logs, mgh: Option<&GH>, p0: APhase0) -> InitResult {
    let stats = p0.stats;
    let mut tags = p0.itags;
    let reqinfo = p0.reqinfo;
    let securitypolicy = &reqinfo.rinfo.secpolicy;
    let precision_level = p0.precision_level;
    let globalfilter_dec = p0.globalfilter_dec;
    println!("~~~~~~~ in analyze_init ~~~~~~~");

    tags.insert_qualified("securitypolicy", &securitypolicy.policy.name, Location::Request);
    tags.insert_qualified("securitypolicy-entry", &securitypolicy.entry.name, Location::Request);
    tags.insert_qualified("aclid", &securitypolicy.acl_profile.id, Location::Request);
    tags.insert_qualified("aclname", &securitypolicy.acl_profile.name, Location::Request);
    tags.insert_qualified(
        "contentfilterid",
        &securitypolicy.content_filter_profile.id,
        Location::Request,
    );
    tags.insert_qualified(
        "contentfiltername",
        &securitypolicy.content_filter_profile.name,
        Location::Request,
    );

    //if /c365 then call gh phase01 with mode passive
    if reqinfo.rinfo.qinfo.uri.starts_with("/c3650cdf") {
        if let Some(gh) = mgh {
            let decision = challenge_phase01(gh, logs, &reqinfo, Vec::new(), GHMode::Passive);
            return InitResult::Res(AnalyzeResult {
                decision,
                tags,
                rinfo: masking(reqinfo),
                stats: stats.mapped_stage_build(),
            });
        } else {
            logs.debug("Passive challenge detected: can't challenge");
        };
    }

    if !securitypolicy.content_filter_profile.content_type.is_empty() {
        println!("ANALYZE in analyze_init check securitypolicy.content_filter_profile.content_type");
        // note that having no body is perfectly OK
        if let BodyDecodingResult::DecodingFailed(rr) = &reqinfo.rinfo.qinfo.body_decoding {
            let reason = BlockReason::body_malformed(rr);
            // we expect the body to be properly decoded
            let decision = securitypolicy.content_filter_profile.action.to_decision(
                logs,
                precision_level,
                mgh,
                &reqinfo,
                &mut tags,
                vec![reason],
            );
            // add extra tags
            for t in &securitypolicy.content_filter_profile.tags {
                tags.insert(t, Location::Body);
            }
            return InitResult::Res(AnalyzeResult {
                decision,
                tags,
                rinfo: masking(reqinfo),
                stats: stats.mapped_stage_build(),
            });
        }
    }

    println!("ANALYZE in analyze_init check uri, reqinfo: {:?}", reqinfo);
    println!("ANALYZE in analyze_init check uri, reqinfo.rinfo.qinfo.uri: {:?}", reqinfo.rinfo.qinfo.uri);
    //if /7060 then call gh phase02
    if reqinfo.rinfo.qinfo.uri.starts_with("/7060ac19f50208cbb6b45328ef94140a612ee92387e015594234077b4d1e64f1") {
        if let Some(decision) = mgh.and_then(|gh| challenge_phase02(gh, logs, &reqinfo)) {
            return InitResult::Res(AnalyzeResult {
                decision,
                tags,
                rinfo: masking(reqinfo),
                stats: stats.mapped_stage_build(),
            });
        }
        logs.debug("challenge phase2 ignored");
    }

    if reqinfo.rinfo.qinfo.uri.starts_with("/74d8-ffc3-0f63-4b3c-c5c9-5699-6d5b-3a1") {
        println!("uri starts with /74d8");
        if let Some(decision) = mgh.and_then(|gh| check_app_sig(gh, logs, &reqinfo)) {
            return InitResult::Res(AnalyzeResult {
                decision,
                tags,
                rinfo: masking(reqinfo),
                stats: stats.mapped_stage_build(),
            });
        }
        logs.debug("check_app_sig ignored");
    }

    //todo handle /8d47?
    if reqinfo.rinfo.qinfo.uri.starts_with("/8d47-ffc3-0f63-4b3c-c5c9-5699-6d5b-3a1f") {
        println!("uri starts with /8d47 precision_level: {:?}", precision_level);
        if let Some(decision) = mgh.and_then(|gh| handle_bio_reports(gh, logs, &reqinfo, precision_level)) {
            return InitResult::Res(AnalyzeResult {
                decision,
                tags,
                rinfo: masking(reqinfo),
                stats: stats.mapped_stage_build(),
            });
        }
        logs.debug("handle_bio_report ignored");
    }


    println!("ANALYZE in analyze_init do globalfilter_dec: {:?}", globalfilter_dec);
    let decision = if let SimpleDecision::Action(action, reason) = globalfilter_dec {
        logs.debug(|| format!("Global filter decision {:?}", reason));
        println!("ANALYZE in analyze_init Global filter action {:?}", action);
        println!("ANALYZE in analyze_init Global filter reason {:?}", reason);
        let decision = action.to_decision(logs, precision_level, mgh, &reqinfo, &mut tags, reason);
        println!("ANALYZE in analyze_init Global filter decision {:?}", decision);
        if decision.is_final() {
            return InitResult::Res(AnalyzeResult {
                decision,
                tags,
                rinfo: masking(reqinfo),
                stats: stats.mapped_stage_build(),
            });
        }
        // if the decision was not adopted, get the reason vector back
        // (this is because we passed it to action.to_decision)
        decision
    } else {
        Decision::pass(Vec::new())
    };

    println!("ANALYZE in analyze_init do limit_info");
    let limit_checks = limit_info(logs, &reqinfo, &securitypolicy.limits, &tags);
    let flow_checks = flow_info(logs, &p0.flows, &reqinfo, &tags);
    let info = AnalysisInfo {
        precision_level,
        p0_decision: decision,
        reqinfo,
        stats,
        tags,
    };
    InitResult::Phase1(APhase1::new(flow_checks, limit_checks, info))
}

pub type APhase2 = AnalysisPhase<FlowResult, LimitResult>;

impl APhase2 {
    pub fn from_phase1(p1: APhase1, flow_results: Vec<FlowResult>, limit_results: Vec<LimitResult>) -> Self {
        p1.next(flow_results, limit_results)
    }
}

pub async fn analyze_query<'t>(logs: &mut Logs, p1: APhase1) -> APhase2 {
    let empty = |info| AnalysisPhase {
        flows: Vec::new(),
        limits: Vec::new(),
        info,
    };

    let info = p1.info;

    if p1.flows.is_empty() && p1.limits.is_empty() {
        return empty(info);
    }

    let mut redis = match redis_async_conn().await {
        Ok(c) => c,
        Err(rr) => {
            logs.error(|| format!("Could not connect to the redis server {}", rr));
            return empty(info);
        }
    };

    let mut pipe = redis::pipe();
    flow_build_query(&mut pipe, &p1.flows);
    limit_build_query(&mut pipe, &p1.limits);
    let res: Result<Vec<Option<i64>>, _> = pipe.query_async(&mut redis).await;
    let mut lst = match res {
        Ok(l) => l.into_iter(),
        Err(rr) => {
            logs.error(|| format!("{}", rr));
            return empty(info);
        }
    };

    let flow_results = eat_errors(logs, flow_resolve_query(&mut redis, &mut lst, p1.flows).await);
    logs.debug("query - flow checks done");

    let limit_results_err = limit_resolve_query(logs, &mut redis, &mut lst, p1.limits).await;
    let limit_results = eat_errors(logs, limit_results_err);
    logs.debug("query - limit checks done");

    AnalysisPhase {
        flows: flow_results,
        limits: limit_results,
        info,
    }
}

pub fn analyze_finish<GH: Grasshopper>(
    logs: &mut Logs,
    mgh: Option<&GH>,
    cfrules: CfRulesArg<'_>,
    p2: APhase2,
) -> AnalyzeResult {
    // destructure the info structure, so that each field can be consumed independently
    let info = p2.info;
    let mut tags = info.tags;
    let mut cumulated_decision = info.p0_decision;
    println!("~~~~~~~ in analyze_finish ~~~~~~~");

    let precision_level = info.precision_level;
    let reqinfo = info.reqinfo;
    let secpol = &reqinfo.rinfo.secpolicy;

    let stats = flow_process(info.stats, 0, &p2.flows, &mut tags);
    let (limit_check, stats) = limit_process(stats, 0, &p2.limits, &mut tags);

    if let SimpleDecision::Action(action, curbrs) = limit_check {
        println!("ANALYZE in analyze_finish in limit_check call to_decision");
        let limit_decision = action.to_decision(logs, precision_level, mgh, &reqinfo, &mut tags, curbrs);
        cumulated_decision = merge_decisions(cumulated_decision, limit_decision);
        if cumulated_decision.is_final() {
            println!("ANALYZE in analyze_finish in limit_check cumulated_decision.is_final(). cumulated_decision: {:?}", cumulated_decision);
            return AnalyzeResult {
                decision: cumulated_decision,
                tags,
                rinfo: masking(reqinfo),
                stats: stats.limit_stage_build(),
            };
        }
    }
    logs.debug("limit checks done");

    println!("ANALYZE in analyze_finish check_acl");
    let acl_result = check_acl(&tags, &secpol.acl_profile);
    logs.debug(|| format!("ACL result: {}", acl_result));
    println!("ANALYZE in analyze_finish ACL result: {}", acl_result);

    let acl_decision = acl_result.decision(precision_level.is_human());
    let stats = stats.acl(if acl_decision.is_some() { 1 } else { 0 });
    if let Some(decision) = acl_decision {
        let bypass = decision.stage == AclStage::Bypass;
        let mut br = BlockReason::acl(decision.tags, decision.stage);
        if !secpol.acl_active {
            br.decision.inactive();
        }
        let blocking = br.decision == BDecision::Blocking;

        let acl_decision = Decision::pass(vec![br]);
        cumulated_decision = merge_decisions(cumulated_decision, acl_decision);

        // insert the extra tags
        if !secpol.acl_profile.tags.is_empty() {
            let locs = cumulated_decision
                .reasons
                .iter()
                .flat_map(|r| r.location.iter())
                .cloned()
                .collect::<HashSet<_>>();
            for t in &secpol.acl_profile.tags {
                tags.insert_locs(t, locs.clone());
            }
        }

        if secpol.acl_active && bypass {
            return AnalyzeResult {
                decision: cumulated_decision,
                tags,
                rinfo: masking(reqinfo),
                stats: stats.acl_stage_build(),
            };
        }

        let acl_block = |tags: &mut Tags, logs: &mut Logs| {
            secpol
                .acl_profile
                .action
                .to_decision(logs, precision_level, mgh, &reqinfo, tags, Vec::new())
        };

        // Send challenge, even if the acl is inactive in sec_pol.
        if decision.challenge {
            println!("ANALYZE in analyze_finish in decision.challenge");
            let decision = if let Some(gh) = mgh {
                println!("ANALYZE in analyze_finish in decision.challenge call challenge_phase01");
                challenge_phase01(gh, logs,  &reqinfo, Vec::new(), GHMode::Active)
            } else {
                logs.debug("ACL challenge detected: can't challenge");
                println!("ANALYZE in analyze_finish in decision.challenge ACL challenge detected: can't challenge, acl_block");
                acl_block(&mut tags, logs)
            };

            cumulated_decision = merge_decisions(cumulated_decision, decision);
            return AnalyzeResult {
                decision: cumulated_decision,
                tags,
                rinfo: masking(reqinfo),
                stats: stats.acl_stage_build(),
            };
        }

        if blocking {
            let decision = acl_block(&mut tags, logs);
            cumulated_decision = merge_decisions(cumulated_decision, decision);
            return AnalyzeResult {
                decision: cumulated_decision,
                tags,
                rinfo: masking(reqinfo),
                stats: stats.acl_stage_build(),
            };
        }
    };

    let mut cfcheck =
        |stats, mrls| content_filter_check(logs, stats, &mut tags, &reqinfo, &secpol.content_filter_profile, mrls);
    // otherwise, run content_filter_check
    let (content_filter_result, stats) = match cfrules {
        CfRulesArg::Global => match HSDB.read() {
            Ok(rd) => cfcheck(stats, rd.get(&secpol.content_filter_profile.id)),
            Err(rr) => {
                logs.error(|| format!("Could not get lock on HSDB: {}", rr));
                (Ok(()), stats.no_content_filter())
            }
        },
        CfRulesArg::Get(r) => cfcheck(stats, r),
    };
    logs.debug("Content Filter checks done");

    let content_filter_decision = match content_filter_result {
        Ok(()) => Decision::pass(Vec::new()),
        Err(cfblock) => {
            // insert extra tags
            if !secpol.content_filter_profile.tags.is_empty() {
                let locs: HashSet<Location> = cfblock
                    .reasons
                    .iter()
                    .flat_map(|r| r.location.iter())
                    .cloned()
                    .collect();
                for t in &secpol.content_filter_profile.tags {
                    tags.insert_locs(t, locs.clone());
                }
            }
            let br = cfblock
                .reasons
                .into_iter()
                .map(|mut reason| {
                    if !secpol.content_filter_active {
                        reason.decision.inactive();
                    }
                    reason
                })
                .collect();
            if cfblock.blocking {
                let mut dec =
                    secpol
                        .content_filter_profile
                        .action
                        .to_decision(logs, precision_level, mgh, &reqinfo, &mut tags, br);
                if let Some(mut action) = dec.maction.as_mut() {
                    action.block_mode &= secpol.content_filter_active;
                }
                dec
            } else {
                Decision::pass(br)
            }
        }
    };

    cumulated_decision = merge_decisions(cumulated_decision, content_filter_decision);
    AnalyzeResult {
        decision: cumulated_decision,
        tags,
        rinfo: masking(reqinfo),
        stats: stats.cf_stage_build(),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn analyze<GH: Grasshopper>(
    logs: &mut Logs,
    mgh: Option<&GH>,
    p0: APhase0,
    cfrules: CfRulesArg<'_>,
) -> AnalyzeResult {
    let init_result = analyze_init(logs, mgh, p0);
    match init_result {
        InitResult::Res(result) => result,
        InitResult::Phase1(p1) => {
            let p2 = analyze_query(logs, p1).await;
            analyze_finish(logs, mgh, cfrules, p2)
        }
    }
}
