public class CmdInj {
    public static void main(String[] args) throws Exception {
        Runtime.getRuntime().exec("ping -c1 " + args[0]);
    }
}
