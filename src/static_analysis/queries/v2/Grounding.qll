import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.ExternalFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.SpelInjection

predicate v2Family(string model, string cwe) {
  model = ["path-injection", "path-injection[read]"] and cwe = "CWE-22"
  or model = "command-injection" and cwe = "CWE-78"
  or model = ["html-injection", "js-injection"] and cwe = "CWE-79"
  or model = ["groovy-injection", "mvel-injection", "jexl-injection", "ognl-injection"]
    and cwe = "CWE-94"
}

predicate v2Source(DataFlow::Node node, string basis) {
  node instanceof RemoteFlowSource and basis = "remote-flow-source"
  or sourceNode(node, "remote") and basis = "modeled-remote-source"
  or
  exists(MethodCall call |
    node.asExpr() = call and
    call.getMethod().getDeclaringType().hasQualifiedName("java.lang", "System") and
    call.getMethod().hasName(["getenv", "getProperty"]) and
    basis = "runtime-configuration-input"
  )
  or
  exists(MethodCall call |
    node.asExpr() = call and call.getMethod().hasName("getName") and
    call.getMethod().getDeclaringType().getAnAncestor().hasQualifiedName("java.util.zip", "ZipEntry")
    and basis = "archive-entry-name"
  )
}

predicate v2Sink(DataFlow::Node node, string cwe, string basis) {
  exists(string model | v2Family(model, cwe) and sinkNode(node, model) and basis = model)
  or node instanceof SpelExpressionEvaluationSink and cwe = "CWE-94" and basis = "spel-evaluation"
  or
  exists(MethodCall call |
    node.asExpr() = call.getArgument(0) and call.getMethod().hasName("eval") and
    call.getMethod().getDeclaringType().getAnAncestor().hasQualifiedName("javax.script", "ScriptEngine")
    and cwe = "CWE-94" and basis = "script-engine-evaluation"
  )
}

predicate v2Barrier(DataFlow::Node node, string cwe) {
  exists(string model | v2Family(model, cwe) and barrierNode(node, model))
}

string v2Callable(Callable callable) {
  result = callable.getDeclaringType().getQualifiedName() + "#" + callable.getSignature()
}

/** Only explicit source-backed expressions and parameters are eligible bindings. */
class V2Node extends DataFlow::Node {
  V2Node() {
    this.getEnclosingCallable().fromSource() and
    (this = DataFlow::exprNode(this.asExpr()) or this = DataFlow::parameterNode(this.asParameter()))
  }

  string getExpressionKind() {
    result = this.asExpr().getAPrimaryQlClass()
    or exists(this.asParameter()) and result = "Parameter"
  }

  string getSlot() {
    this.asExpr() instanceof Call and result = "return"
    or
    exists(Call call, int index |
      not this.asExpr() instanceof Call and
      call.getArgument(index) = this.asExpr() and result = "argument:" + index.toString()
    )
    or exists(Parameter parameter |
      parameter = this.asParameter() and result = "parameter:" + parameter.getPosition().toString()
    )
    or exists(MethodCall call |
      not this.asExpr() instanceof Call and
      call.getQualifier() = this.asExpr() and result = "receiver"
    )
    or
    not exists(Call call | call.getAnArgument() = this.asExpr()) and
    not exists(MethodCall call | call.getQualifier() = this.asExpr()) and
    not this.asExpr() instanceof Call and
    not exists(this.asParameter()) and result = "expression"
  }

  string getTargetSignature() {
    exists(Call call |
      (call = this.asExpr()
       or not this.asExpr() instanceof Call and
         (call.getAnArgument() = this.asExpr()
          or call.(MethodCall).getQualifier() = this.asExpr())) and
      result = v2Callable(call.getCallee())
    )
    or
    not exists(Call call |
      call = this.asExpr() or call.getAnArgument() = this.asExpr()
      or call.(MethodCall).getQualifier() = this.asExpr()
    ) and
    result = ""
  }

  string getDataFlowKind() {
    exists(this.asExpr()) and result = "expr"
    or exists(this.asParameter()) and result = "parameter"
  }
}

/** A source call's return and its consumption as a sink argument are distinct bindings. */
string v2Slot(V2Node node, string role) {
  role = ["source", "sink"] and (
  role = "sink" and
  exists(Call call, int index |
    call.getArgument(index) = node.asExpr() and result = "argument:" + index.toString()
  )
  or role = "sink" and exists(MethodCall call |
    call.getQualifier() = node.asExpr() and result = "receiver"
  )
  or
  (role = "source" or not exists(Call call |
    call.getAnArgument() = node.asExpr() or call.(MethodCall).getQualifier() = node.asExpr()
  )) and result = node.getSlot()
  )
}

string v2TargetSignature(V2Node node, string role) {
  role = ["source", "sink"] and (
  role = "sink" and exists(Call call |
    (call.getAnArgument() = node.asExpr() or call.(MethodCall).getQualifier() = node.asExpr())
    and result = v2Callable(call.getCallee())
  )
  or
  (role = "source" or not exists(Call call |
    call.getAnArgument() = node.asExpr() or call.(MethodCall).getQualifier() = node.asExpr()
  )) and result = node.getTargetSignature()
  )
}


module V2DiscoveryConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { v2Source(node, _) }
  predicate isSink(DataFlow::Node node) { v2Sink(node, _, _) }
  // Discovery is deliberately unverified. CWE-specific barriers are applied by verifier v3.
}
module V2DiscoveryFlow = TaintTracking::Global<V2DiscoveryConfig>;

predicate v2CallStep(Callable caller, Callable callee) {
  exists(Call call |
    call.getEnclosingCallable() = caller and call.getCallee().getSourceDeclaration() = callee
  )
}

predicate v2CandidateRelation(V2Node source, V2Node sink, string evidenceKind) {
  V2DiscoveryFlow::flow(source, sink) and evidenceKind = "GLOBAL_TAINT_CANDIDATE"
  or source.getEnclosingCallable() = sink.getEnclosingCallable()
    and evidenceKind = "SAME_CALLABLE_NO_FLOW_PROOF"
  or
  (v2CallStep(source.getEnclosingCallable(), sink.getEnclosingCallable())
   or exists(Callable middle |
     v2CallStep(source.getEnclosingCallable(), middle) and
     v2CallStep(middle, sink.getEnclosingCallable())
   )) and evidenceKind = "CALL_BOUNDARY_NO_FLOW_PROOF"
}
