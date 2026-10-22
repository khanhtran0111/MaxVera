class Parent { String transform(String x) { return x; } }
class Child extends Parent { @Override String transform(String x) { return x.trim(); } }
class LanguageEdges {
    void demonstrate(String external) {
        Parent receiver = new Child();
        Runnable action = () -> System.out.println(receiver.transform(external));
        try { action.run(); } catch (RuntimeException missingExternalSummary) { }
    }
}
