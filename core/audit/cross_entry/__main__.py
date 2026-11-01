"""Offline structural pilot: python -m core.audit.cross_entry TARGET --out DIR."""
import argparse
from pathlib import Path

from .integration import prepare_cross_entry
from .model import Limits


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target",type=Path)
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--context-root",type=Path)
    parser.add_argument("--include-dir",type=Path,action="append",default=[],
                        help="Header search directory; follows referenced headers only (repeatable)")
    parser.add_argument("--report",action="append",default=[],metavar="FILE:FUNCTION")
    parser.add_argument("--mode",choices=["index","shadow","context","study"],default="shadow")
    parser.add_argument("--drain-index",action="store_true")
    parser.add_argument("--index-batch-files",type=int,default=200)
    parser.add_argument("--max-files",type=int,default=200)
    parser.add_argument("--max-calls",type=int,default=8)
    parser.add_argument("--max-slices",type=int,default=40)
    parser.add_argument("--functions-per-slice",type=int,default=12)
    parser.add_argument("--graph-depth",type=int,default=3)
    parser.add_argument("--source-chars",type=int,default=24000)
    parser.add_argument("--input-tokens",type=int,default=12000)
    parser.add_argument("--model")
    parser.add_argument("--max-cost",type=float,help="Model cost cap for this continuation")
    parser.add_argument("--acknowledge-context",action="store_true",
                        help="Mark the previously exported context receipts consumed before continuing")
    args = parser.parse_args()
    if args.max_cost is not None and args.max_cost <= 0:
        parser.error("--max-cost must be positive")
    if not args.report and args.mode != "index":
        parser.error("at least one --report FILE:FUNCTION is required")
    gaps = []
    for report in args.report:
        fp,sep,name = report.partition(":")
        if not sep or not fp or not name:
            parser.error("--report must be FILE:FUNCTION")
        gaps.append({"file":fp,"name":name})
    limits = Limits(max_files=args.max_files,max_calls=args.max_calls,max_slices=args.max_slices,
                    functions_per_slice=args.functions_per_slice,graph_depth=args.graph_depth,
                    source_chars=args.source_chars,input_tokens=args.input_tokens,index_batch_files=args.index_batch_files)
    if args.acknowledge_context:
        from core.json import load_json
        from .progress import acknowledge_delivery
        previous = load_json(args.out/"cross-entry-delivery.json") or {}
        for receipt in previous.get("receipts",{}).values():
            acknowledge_delivery(args.out,receipt)
    client = None
    if args.mode == "study":
        from core.llm.transcript import build_llm_client
        client = build_llm_client(pinned_model=args.model)
        if args.max_cost is not None:
            client.config.max_cost_per_scan = args.max_cost
    contexts = prepare_cross_entry(args.target,gaps,mode=args.mode,out_dir=args.out,context_root=args.context_root,
        limits=limits,client=client,model_key=args.model or "configured",drain_index=args.drain_index,
        include_dirs=args.include_dir)
    from core.json import load_json
    progress = load_json(args.out/"cross-entry-progress.json") or {}
    print(f"Artifacts: {args.out}; contexts: {len(contexts)}; remaining jobs: {progress.get('remaining_jobs',0)}; "
          f"index complete: {progress.get('indexing',{}).get('index_complete',False)}")


if __name__ == "__main__":
    main()
