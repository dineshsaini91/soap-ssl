
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.security.KeyStore;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.xml.ws.BindingProvider;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Map;
import javax.net.ssl.X509TrustManager;

public class SSLSOAPClient {

    public static void main(String[] args) {

    }

    private void hitSoapService() {
        try {
            ProxySelector.setDefault(new MyProxySelector());

            //_Service service = new _Service();
            //WebService port = service.getWebServicePort();
            //BindingProvider bindingProvider = (BindingProvider) port;
            Map<String, Object> requestContext = null;// = bindingProvider.getRequestContext();

            String urlSoapService = "";
            int timeout = 120000;//ms

            requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, urlSoapService);
            requestContext.put("com.sun.xml.internal.ws.request.timeout", timeout);
            requestContext.put("com.sun.xml.internal.ws.transport.https.client.SSLSocketFactory", getSocketFactory());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private Object getSocketFactory() {
        try {
            String certLocation = "D:/cert.pfx";

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream(new File(certLocation)), "pwd".toCharArray());

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, "pwd".toCharArray());
            KeyManager[] kms = kmf.getKeyManagers();

            TrustManager[] tms = new TrustManager[]{new X509TrustManager() {
                @Override
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                @Override
                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException {
                    //                    if (certs == null || certs.length == 0) {
//                        throw new IllegalArgumentException("null or zero-length certificate chain");
//                    }
//                    if (authType == null || authType.length() == 0) {
//                        throw new IllegalArgumentException("null or zero-length authentication type");
//                    }
//                    if (!certs[0].equals(trusted)) {
//                        try {
//                            certs[0].verify(trusted.getPublicKey());
//                        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
//                            throw new CertificateException(e);
//                        }
//                    }
                    //certs[0].checkValidity();
                }
            }};
            final SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(kms, tms, new SecureRandom());
            SSLContext.setDefault(sslContext);

            return sslContext.getSocketFactory();

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    class MyProxySelector extends ProxySelector {

        @Override
        public List<Proxy> select(URI uri) {
            Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("proxy.host", 8080));
            ArrayList<Proxy> list = new ArrayList<>();
            list.add(proxy);
            return list;
        }

        @Override
        public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
            System.err.println("Connection to " + uri + " failed.");
        }
    }

}
