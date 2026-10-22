import Grounding

/** Stable within a source snapshot; role-independent to merge source/sink bindings. */
string programKey(V2Node node) {
  exists(Location loc |
    loc = node.getLocation() and
    result = loc.getFile().getRelativePath() + ":" + loc.getStartLine().toString() + ":" +
      loc.getStartColumn().toString() + ":" + loc.getEndLine().toString() + ":" +
      loc.getEndColumn().toString() + ":" + node.getDataFlowKind() + ":" +
      node.getExpressionKind() + ":" + v2Callable(node.getEnclosingCallable())
  )
}

predicate programSink(DataFlow::Node node) {
  v2Sink(node, _, _)
  or sinkNode(node, ["sql-injection", "ldap-injection", "xpath-injection", "url-redirection"])
}

string programRole(V2Node node) {
  v2Source(node, _) and result = "source"
  or programSink(node) and result = "sink"
  or barrierNode(node, ["sql-injection", "command-injection", "path-injection", "html-injection"])
    and result = "guard"
  or not v2Source(node, _) and not programSink(node) and
    not barrierNode(node, ["sql-injection", "command-injection", "path-injection", "html-injection"])
    and result = ""
}

predicate programEdge(V2Node source, V2Node target, string kind) {
  TaintTracking::localTaintStep(source, target) and kind = "MAY_FLOW"
  or
  exists(Call call, Parameter parameter |
    call.getCallee().getSourceDeclaration() = parameter.getCallable() and
    source.asExpr() = call.getArgument(parameter.getPosition()) and
    target.asParameter() = parameter and kind = "ARG_TO_PARAM"
  )
  or
  exists(Call call, ReturnStmt ret |
    call.getCallee().getSourceDeclaration() = ret.getEnclosingCallable() and
    source.asExpr() = ret.getResult() and target.asExpr() = call and kind = "RET_TO_CALL"
  )
}
