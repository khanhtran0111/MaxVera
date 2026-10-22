/**
 * @name MaxVera local conservative flow and resolved cross-file parameter/return edges
 * @kind table
 * @id java/maxvera/v2/program-edges
 */
import ProgramCore
from V2Node sourceNode, V2Node targetNode, string kind
where programEdge(sourceNode, targetNode, kind)
select programKey(sourceNode) as source, programKey(targetNode) as target, kind
