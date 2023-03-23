import java.util.Arrays;

public class LCP {

//Longest Common Prefix (LCP) Problem
    public static void main(String[] args) throws Exception {


        //enter your input HERE:
        String input = "bddbbadcaccaccac";

        System.out.println("\n----------------------------------");
        System.out.println("INPUT:");
        System.out.println("----------------------------------");
        System.out.println(input);

        System.out.println("\n----------------------------------");
        System.out.println("Suffixes:");
        System.out.println("----------------------------------");
        String str = input;
        String[] results = new String[input.length()];
        for (int i = 0; i <input.length();i++)
        {

            System.out.print(str+"\n");

            results[i]=str;


            str = str.substring(1);
        }
        System.out.println("\n----------------------------------");
        System.out.println("Suffixes in lexicographic order:");
        System.out.println("----------------------------------");

        Arrays.sort(results);
        for (int i = 0; i < results.length; i++){

            System.out.println(results[i]);
        }
        System.out.println("\n----------------------------------");
        System.out.println("LCP array:");
        System.out.println("----------------------------------");
        System.out.print("0");

        for(int i = 1; i < results.length; i++){
            System.out.print(",");
            int x = 0;
            int y = 0;
            while (x < results[i-1].length() && y < results[i].length())
            {
                if (results[i-1].charAt(x) != results[i].charAt(y)) {
                    break;
                }
                x++; y++;
            }
            System.out.print(x);
        }
        System.out.println("\n");
    }
}
