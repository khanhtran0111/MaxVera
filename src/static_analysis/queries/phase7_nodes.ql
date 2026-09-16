/**
 * @name MaxVera Phase 7 source-backed Java program nodes
 * @description Extracts bounded descriptors for source-backed security-relevant program nodes.
 * @kind table
 * @id java/maxvera/phase7-program-nodes
 */

import Phase7Graph

from Phase7ProgramNode node, Location nodeLocation
where nodeLocation = node.getLocation()
select
  node.getNodeKind() as node_kind,
  node.getSubkind() as node_subkind,
  nodeLocation.getFile().getRelativePath() as node_file,
  nodeLocation.getStartLine() as node_start_line,
  nodeLocation.getStartColumn() as node_start_column,
  nodeLocation.getEndLine() as node_end_line,
  nodeLocation.getEndColumn() as node_end_column,
  node.getSymbol() as node_symbol,
  node.getTypeName() as node_type_name
