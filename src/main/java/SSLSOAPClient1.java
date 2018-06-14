
import java.io.File;
import java.io.FileInputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

public class SSLSOAPClient1 {

    private static Object getCustomSocketFactory() {
        String PFX_LOCATION = "path/to/cert.pfx";
        String PWD = "pwd";
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream(new File(PFX_LOCATION)), PWD.toCharArray());

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, PWD.toCharArray());
            KeyManager[] kms = kmf.getKeyManagers();

            // Assuming that you imported the CA Cert "Subject: CN=MBIIS CA, OU=MBIIS, O=DAIMLER, C=DE"
            // to your cacerts Store.
            /*KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream("cacerts"), "changeit".toCharArray());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            TrustManager[] tms = tmf.getTrustManagers();*/
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
            Logger.getLogger(SSLSOAPClient1.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    private static SSLSocketFactory loadKeyStore() {
        String PKS_LOCATION = "path/to/cert.jks";
        String PWD = "pwd";
        try {
            FileInputStream is = new FileInputStream(new File(PKS_LOCATION));

            final KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(is, PWD.toCharArray());

            final Certificate trusted = keystore.getCertificate("certalias");

            /*
             * Create a trust manager that validates the servers certificate
             */
            TrustManager[] trustManager = new TrustManager[]{new X509TrustManager() {
                @Override
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                @Override
                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException {

                    System.out.println("INSIDE checkServerTrusted()");

                    if (certs == null || certs.length == 0) {
                        throw new IllegalArgumentException("null or zero-length certificate chain");
                    }

                    if (authType == null || authType.length() == 0) {
                        throw new IllegalArgumentException("null or zero-length authentication type");
                    }
                    // check if certificate sent is your CA's
                    if (!certs[0].equals(trusted)) {
                        // check if its been signed by the CA
                        try {
                            certs[0].verify(trusted.getPublicKey());
                        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
                            throw new CertificateException(e);
                        }
                    }
                    certs[0].checkValidity();
                }
            }};

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keystore, PWD.toCharArray());

            // set the trust manager
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(kmf.getKeyManagers(), trustManager, new java.security.SecureRandom());

            //HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            // create an all-trusting host name verifier
//            HostnameVerifier allHostsValid = new HostnameVerifier() {
//                @Override
//                public boolean verify(String hostname, SSLSession session) {
//                    return true;
//                }
//            };
            //HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
            return sc.getSocketFactory();
        } catch (Exception e) {
            System.err.println("Error in ssl connection : " + e);
        }
        return null;
    }

}
