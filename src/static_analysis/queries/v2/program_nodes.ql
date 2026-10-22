/**
 * @name MaxVera source-backed generic program nodes
 * @kind table
 * @id java/maxvera/v2/program-nodes
 */
import ProgramCore
from V2Node node, Location loc
where loc = node.getLocation()
select programKey(node) as key, loc.getFile().getRelativePath() as file,
  loc.getStartLine() as start_line, loc.getStartColumn() as start_column,
  loc.getEndLine() as end_line, loc.getEndColumn() as end_column,
  node.getExpressionKind() as kind, v2Callable(node.getEnclosingCallable()) as symbol,
  programRole(node) as role, node.toString() as expression
