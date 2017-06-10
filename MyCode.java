/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package implementation;

import code.GuiException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.util.Enumeration;
import java.util.List;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;



/**
 *
 * @author ivan
 */
public class MyCode extends x509.v3.CodeV3 {

    private static final String keystore_name = "localkeystore.p12";
    private static final String keystore_pass = "root";
    private static KeyStore keystore = null;

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
        super(algorithm_conf, extensions_conf);

        this.access.setVersion(2);
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {

        try {

            keystore = KeyStore.getInstance("pkcs12");

            File file = new File(keystore_name);
            if(!file.exists()) {
                keystore.load(null, null);
                FileOutputStream fos = new FileOutputStream(keystore_name, true);
                keystore.store(fos, keystore_pass.toCharArray());
                fos.close();
            }

            FileInputStream fis = new FileInputStream(keystore_name);
            keystore.load(fis, keystore_pass.toCharArray());
            fis.close();

            return keystore.aliases();

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    @Override
    public void resetLocalKeystore() {
        try {
            keystore.load(null, null);
            FileOutputStream fos = new FileOutputStream(keystore_name);
            keystore.store(fos, keystore_pass.toCharArray());
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        loadLocalKeystore();
    }

    private String parse(String s, String key) {

        int start = s.indexOf(key) + key.length();
        try {
            int end = s.substring(start).indexOf(',');
            return s.substring(start, start+end);
        }
        catch (Exception e) {

        }
        return s.substring(start);
    }


    @Override
    public int loadKeypair(String string){
        try {
            //
            //X509Certificate[] certs = (X509Certificate[]) keystore.getCertificateChain(string);
            X509CertImpl cert = (X509CertImpl) keystore.getCertificate(string);

            BigInteger serialNumber = cert.getSerialNumber();
            access.setSerialNumber(serialNumber.toString());

            String params = cert.getSubjectDN().toString();
            String CN = "", OU = "", O = "", L = "", ST = "", C = "";
            CN = parse(params, "CN=");
            OU = parse(params, "OU=");
            O = parse(params, "O=");
            L = parse(params, "L=");
            ST = parse(params, "ST=");
            C = parse(params, "C=");

            access.setSubjectCommonName(CN);
            access.setSubjectCountry(C);
            access.setSubjectLocality(L);
            access.setSubjectOrganization(O);
            access.setSubjectOrganizationUnit(OU);
            access.setSubjectState(ST);

            // return stuff
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
        return 0;
    }

    @Override
    public boolean saveKeypair(String string) {
        try {
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("DSA");
            //keygen.initialize();
            KeyPair keypair = keygen.generateKeyPair();

            PrivateKey privatekey = keypair.getPrivate();
            PublicKey publickey = keypair.getPublic();

            String CN = "", OU = "", O = "", L = "", ST = "", C = "";

            if (access.getSubjectCommonName() != null && !access.getSubjectCommonName().isEmpty()) {
                CN = access.getSubjectCommonName();
            }
            if (access.getSubjectCountry() != null && !access.getSubjectCountry().isEmpty()) {
                C = access.getSubjectCountry();
            }
            if (access.getSubjectLocality() != null && !access.getSubjectLocality().isEmpty()) {
                L = access.getSubjectLocality();
            }
            if (access.getSubjectOrganization() != null && !access.getSubjectOrganization().isEmpty()) {
                O = access.getSubjectOrganization();
            }
            if (access.getSubjectOrganizationUnit() != null && !access.getSubjectOrganizationUnit().isEmpty()) {
                OU = access.getSubjectOrganizationUnit();
            }
            if (access.getSubjectState() != null && !access.getSubjectState().isEmpty()) {
                ST = access.getSubjectState();
            }

            String params = "CN=" + CN + ",C=" + C + ",L=" + L + ",O=" + O + ",OU=" + OU + ",ST=" + ST;

            X509CertInfo info = new X509CertInfo();

            Date from = access.getNotBefore();
            Date to = access.getNotAfter();
            CertificateValidity interval = new CertificateValidity(from, to);

            BigInteger serialNumber = null;
            if(access.getSerialNumber() != null && !access.getSerialNumber().isEmpty())
                serialNumber = new BigInteger(access.getSerialNumber());

            X500Name owner = new X500Name(params);

            info.set(X509CertInfo.VALIDITY, interval);
            info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNumber));

            info.set(X509CertInfo.SUBJECT, owner);
            info.set(X509CertInfo.ISSUER, owner);
            info.set(X509CertInfo.KEY, new CertificateX509Key(publickey));

            info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
            AlgorithmId algo = new AlgorithmId(AlgorithmId.sha1WithDSA_oid);
            info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));

            X509CertImpl cert = new X509CertImpl(info);

            cert.sign(privatekey, "SHA1withDSA");

            FileOutputStream outputStream = new FileOutputStream(keystore_name);

            keystore.setKeyEntry(string, privatekey, keystore_pass.toCharArray(), new X509Certificate[] {cert});
            keystore.store(outputStream, keystore_pass.toCharArray());
            outputStream.close();

            return true;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            ex.printStackTrace();
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }

        return false;
    }

    @Override
    public boolean removeKeypair(String string) {
        try{
            if (keystore.containsAlias(string)) {
                keystore.deleteEntry(string);
                return true;
            }
        } catch(Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    @Override
    public boolean importKeypair(String keypair_name, String file_path, String password) {
        try {

            KeyStore tmp_keystore = KeyStore.getInstance("pkcs12");
            tmp_keystore.load(null, null);
            FileInputStream fis = new FileInputStream(file_path);
            Provider p = tmp_keystore.getProvider();
            tmp_keystore.load(fis, password.toCharArray());
            fis.close();

            Key private_key = (PrivateKey) tmp_keystore.getKey(keypair_name, password.toCharArray());

            keystore.setKeyEntry(keypair_name, private_key, keystore_pass.toCharArray(), tmp_keystore.getCertificateChain(keypair_name));

            keystore.store(new FileOutputStream(keystore_name), keystore_pass.toCharArray());

            return true;
        } catch(Exception e) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, e);
            return false;
        }
    }

    @Override
    public boolean exportKeypair(String keypair_name, String file_path, String password) {
        try {
            KeyStore tmp_keystore = KeyStore.getInstance("pkcs12");

            FileOutputStream fos = new FileOutputStream(file_path + ".p12");
            tmp_keystore.load(null, null);

            Key private_key = (PrivateKey) keystore.getKey(keypair_name, keystore_pass.toCharArray());

            tmp_keystore.setKeyEntry(keypair_name, private_key, password.toCharArray(), keystore.getCertificateChain(keypair_name));

            tmp_keystore.store(fos, password.toCharArray());
            fos.close();
            return true;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

    }

    @Override
    public boolean signCertificate(String string, String string1) {

        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean importCertificate(File file, String string) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean exportCertificate(File file, int i) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public String getIssuer(String string) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public String getIssuerPublicKeyAlgorithm(String string) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public int getRSAKeyLength(String string) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public List<String> getIssuers(String string) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean generateCSR(String string) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

}
