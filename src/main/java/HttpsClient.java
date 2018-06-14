
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.Certificate;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.Proxy;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;

public class HttpsClient {

    public static void main(String[] args) {
        new HttpsClient().testIt();
    }

    private void testIt() {
        String https_url = "https://www.google.com/";
        URL url;
        try {
//            URLConnection openConnection = url.openConnection();InputStream inputStream = openConnection.getInputStream();
//            List<String> readLines = IOUtils.readLines(inputStream, "UTF-8");
//            System.out.println(readLines);
            Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("proxy.com", 8080));
            url = new URL(https_url);
            HttpsURLConnection con = (HttpsURLConnection) url.openConnection(proxy);
            //HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
            System.out.println(con.getResponseCode());

            //dumpl all cert info
            print_https_cert(con);
            //dump all the content
            print_content(con);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private void print_https_cert(HttpsURLConnection con) {
        if (con != null) {
            try {
                System.out.println("Response Code : " + con.getResponseCode());
                System.out.println("Cipher Suite : " + con.getCipherSuite());
                System.out.println("\n");

                Certificate[] certs = con.getServerCertificates();
                for (Certificate cert : certs) {
                    System.out.println("Cert Type : " + cert.getType());
                    System.out.println("Cert Hash Code : " + cert.hashCode());
                    System.out.println("Cert Public Key Algorithm : "
                            + cert.getPublicKey().getAlgorithm());
                    System.out.println("Cert Public Key Format : "
                            + cert.getPublicKey().getFormat());
                    System.out.println("\n");
                }
            } catch (SSLPeerUnverifiedException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void print_content(HttpsURLConnection con) {
        if (con != null) {
            try {
                System.out.println("****** Content of the URL ********");
                BufferedReader br
                        = new BufferedReader(
                                new InputStreamReader(con.getInputStream()));

                String input;

                while ((input = br.readLine()) != null) {
                    System.out.println(input);
                }
                br.close();

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

}
