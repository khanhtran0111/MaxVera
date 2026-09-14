/**
 * @name MaxVera Phase 7 source-backed Java program nodes
 * @description Extracts bounded descriptors for source-backed security-relevant program nodes.
 * @kind table
 * @id java/maxvera/phase7-program-nodes
 */

import Phase7Graph

from Phase7ProgramNode node
select
  node.getNodeKind() as node_kind,
  node.getSubkind() as node_subkind,
  node.getFile().getRelativePath() as node_file,
  node.getLocation().getStartLine() as node_start_line,
  node.getLocation().getStartColumn() as node_start_column,
  node.getLocation().getEndLine() as node_end_line,
  node.getLocation().getEndColumn() as node_end_column,
  node.getSymbol() as node_symbol,
  node.getTypeName() as node_type_name
