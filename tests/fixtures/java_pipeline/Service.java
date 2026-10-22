public class Service {
    public static void dispatch(String value) throws Exception {
        Repository.run(value);
    }
    public static void dispatch(int number) { }
}
