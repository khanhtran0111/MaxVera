/**
 * @name MaxVera Phase 7 Java program edges
 * @description Extracts source-backed AST, call, def-use, flow, control, type, and taint-candidate edges.
 * @kind table
 * @id java/maxvera/phase7-program-edges
 */

import Phase7Graph
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.DefUse
import semmle.code.java.dataflow.TaintTracking

predicate phase7Edge(string edgeKind, Phase7ProgramNode source, Phase7ProgramNode target) {
  phase7AstEdge(source, target) and edgeKind = "AST_PARENT"
  or
  phase7CallEdge(source, target) and edgeKind = "CALL"
  or
  exists(VariableUpdate definition, VarRead use |
    defUsePair(definition, use) and
    source = definition and
    target = use and
    edgeKind = "DEF_USE"
  )
  or
  exists(DataFlow::Node sourceNode, DataFlow::Node targetNode |
    DataFlow::localFlowStep(sourceNode, targetNode) and
    sourceNode.asExpr() = source and
    targetNode.asExpr() = target and
    edgeKind = "DATA_FLOW"
  )
  or
  phase7ControlDependencyEdge(source, target) and edgeKind = "CONTROL_DEP"
  or
  phase7TypeEdge(source, target) and edgeKind = "TYPE"
  or
  exists(DataFlow::Node sourceNode, DataFlow::Node targetNode |
    TaintTracking::localTaintStep(sourceNode, targetNode) and
    sourceNode.asExpr() = source and
    targetNode.asExpr() = target and
    edgeKind = "TAINT_CANDIDATE"
  )
}

from string edgeKind, Phase7ProgramNode source, Phase7ProgramNode target
where phase7Edge(edgeKind, source, target)
select
  edgeKind as edge_kind,
  source.getNodeKind() as source_kind,
  source.getSubkind() as source_subkind,
  source.getFile().getRelativePath() as source_file,
  source.getLocation().getStartLine() as source_start_line,
  source.getLocation().getStartColumn() as source_start_column,
  source.getLocation().getEndLine() as source_end_line,
  source.getLocation().getEndColumn() as source_end_column,
  source.getSymbol() as source_symbol,
  source.getTypeName() as source_type_name,
  target.getNodeKind() as target_kind,
  target.getSubkind() as target_subkind,
  target.getFile().getRelativePath() as target_file,
  target.getLocation().getStartLine() as target_start_line,
  target.getLocation().getStartColumn() as target_start_column,
  target.getLocation().getEndLine() as target_end_line,
  target.getLocation().getEndColumn() as target_end_column,
  target.getSymbol() as target_symbol,
  target.getTypeName() as target_type_name
