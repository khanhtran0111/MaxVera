/**
 * @name MaxVera v2 typed endpoint inventory
 * @kind table
 * @id java/maxvera/v2/endpoints
 */
import Grounding

from V2Node node, string role, string cwe, string basis, Location location
where
  location = node.getLocation() and
  (role = "source" and cwe = "" and v2Source(node, basis)
   or role = "sink" and v2Sink(node, cwe, basis))
select role, cwe, basis, node as resolved_node,
  location.getFile().getRelativePath() as file,
  location.getStartLine() as start_line, location.getStartColumn() as start_column,
  location.getEndLine() as end_line, location.getEndColumn() as end_column,
  v2Callable(node.getEnclosingCallable()) as enclosing_callable,
  node.getExpressionKind() as expression_kind,
  node.getDataFlowKind() as dataflow_kind,
  v2Slot(node, role) as slot, v2TargetSignature(node, role) as target_signature,
  node.toString() as expression
