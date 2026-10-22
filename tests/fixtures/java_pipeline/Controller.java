public class Controller {
    public static void handle() throws Exception {
        Service.dispatch(System.getenv("PIPELINE_INPUT"));
    }
}
