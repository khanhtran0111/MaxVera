/**
 * @name MaxVera v2 source sink discovery pairs
 * @kind table
 * @id java/maxvera/v2/discovery-pairs
 */
import Grounding

from V2Node source, V2Node sink, string cwe, string evidence_kind, Location sourceLocation, Location sinkLocation
where
  v2Source(source, _) and v2Sink(sink, cwe, _) and
  v2CandidateRelation(source, sink, evidence_kind) and
  sourceLocation = source.getLocation() and sinkLocation = sink.getLocation()
select cwe, evidence_kind,
  sourceLocation.getFile().getRelativePath() as source_file,
  sourceLocation.getStartLine() as source_line, sourceLocation.getStartColumn() as source_column,
  sourceLocation.getEndLine() as source_end_line, sourceLocation.getEndColumn() as source_end_column,
  source.getDataFlowKind() as source_dataflow_kind,
  sinkLocation.getFile().getRelativePath() as sink_file,
  sinkLocation.getStartLine() as sink_line, sinkLocation.getStartColumn() as sink_column,
  sinkLocation.getEndLine() as sink_end_line, sinkLocation.getEndColumn() as sink_end_column,
  sink.getDataFlowKind() as sink_dataflow_kind
