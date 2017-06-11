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
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
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
    private static String currentKeypair = null;

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

                
        int start = s.indexOf(key);
        if(start == -1)
            return "";
        start += key.length();
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
            //X509CertImpl cert = (X509CertImpl) keystore.getCertificate(string);

            X509Certificate cert = (X509Certificate) keystore.getCertificate(string);
            currentKeypair = string;

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
            
            if (keystore.getCertificateChain(string) != null) {
                Certificate[] chain = keystore.getCertificateChain(string);
                X509Certificate issuer = (X509Certificate) chain[chain.length-1];
                access.setIssuerSignatureAlgorithm(issuer.getSigAlgName());
            }

            if (!(keystore.getKey(string, keystore_pass.toCharArray()) instanceof PrivateKey)) {
                return 2; //trusted
            } else if (keystore.getCertificateChain(string).length > 1) {
                return 1; //signed
            } else 
                return 0; //not signed
        } catch (Exception ex) {
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

            org.bouncycastle.asn1.x500.X500Name subjectDN = new org.bouncycastle.asn1.x500.X500Name(params);
            org.bouncycastle.asn1.x500.X500Name issuer = new org.bouncycastle.asn1.x500.X500Name(params);
            
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, new BigInteger(access.getSerialNumber()), access.getNotBefore(), access.getNotAfter(), subjectDN, publickey);
            ContentSigner signer = new JcaContentSignerBuilder(access.getPublicKeySignatureAlgorithm()).build(privatekey);
            
            
            Provider bc = new BouncyCastleProvider();
            Security.addProvider(bc);
            
            BasicConstraints basic_constraint = new BasicConstraints(true);
            
            builder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basic_constraint);
            
            X509CertificateHolder holder = builder.build(signer);
            X509Certificate cert = new JcaX509CertificateConverter().setProvider(bc).getCertificate(holder);
            
//            X509CertInfo info = new X509CertInfo();
//
//            Date from = access.getNotBefore();
//            Date to = access.getNotAfter();
//            CertificateValidity interval = new CertificateValidity(from, to);
//
//            BigInteger serialNumber = null;
//            if(access.getSerialNumber() != null && !access.getSerialNumber().isEmpty())
//                serialNumber = new BigInteger(access.getSerialNumber());
//
//            X500Name owner = new X500Name(params);
//
//            owner.getCommonName();
//            
//            info.set(X509CertInfo.VALIDITY, interval);
//            info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNumber));
//
//            info.set(X509CertInfo.SUBJECT, owner);
//            info.set(X509CertInfo.ISSUER, owner);
//            info.set(X509CertInfo.KEY, new CertificateX509Key(publickey));
//            
//            info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
//            AlgorithmId algo = new AlgorithmId(AlgorithmId.sha1WithDSA_oid);
//            info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));
//
//            X509CertImpl cert = new X509CertImpl(info);
//
//            cert.sign(privatekey, "SHA1withDSA");
//
            FileOutputStream outputStream = new FileOutputStream(keystore_name);

            keystore.setKeyEntry(string, privatekey, keystore_pass.toCharArray(), new X509Certificate[] {cert});
            keystore.store(outputStream, keystore_pass.toCharArray());
            outputStream.close();

            return true;
        } catch (Exception ex) {
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
    public boolean signCertificate(String issuer, String algorithm) {
        try {
            PrivateKey private_key = (PrivateKey) keystore.getKey(issuer, keystore_pass.toCharArray());
            X509Certificate cert = (X509Certificate) keystore.getCertificate(issuer);
            
            PrivateKey private_key_subject = (PrivateKey) keystore.getKey(currentKeypair, keystore_pass.toCharArray());
            X509Certificate cert_subject = (X509Certificate) keystore.getCertificate(currentKeypair);
            
            org.bouncycastle.asn1.x500.X500Name name = new org.bouncycastle.asn1.x500.X500Name(cert_subject.getSubjectX500Principal().getName());
            org.bouncycastle.asn1.x500.X500Name issuerName = new org.bouncycastle.asn1.x500.X500Name(cert.getSubjectX500Principal().getName());
            
            
            JcaX509v1CertificateBuilder builder_v1 = new JcaX509v1CertificateBuilder(issuerName, cert_subject.getSerialNumber(), cert_subject.getNotBefore(), cert_subject.getNotAfter(), name, cert_subject.getPublicKey());
            
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(cert, cert_subject.getSerialNumber(), cert_subject.getNotBefore(), cert_subject.getNotAfter(), name, cert_subject.getPublicKey());
            
            ContentSigner signer = new JcaContentSignerBuilder(algorithm).build(private_key);
            X509CertificateHolder holder;
            if(cert_subject.getVersion() == 1) {
                holder = builder_v1.build(signer);
            } else {
                holder = builder.build(signer);
            }
            
            X509Certificate cert_new = new JcaX509CertificateConverter().getCertificate(holder);
            
            Certificate[] certs = keystore.getCertificateChain(issuer);
            Certificate[] new_certs = new Certificate[certs.length + 1];
            
            int i = 0;
            new_certs[0] = cert_new;
            for (i = 0; i < certs.length; i++)
                new_certs[i+1] = certs[i];
            
            keystore.deleteEntry(currentKeypair);
            keystore.setKeyEntry(currentKeypair, private_key_subject, keystore_pass.toCharArray(), new_certs);
            keystore.store(new FileOutputStream(keystore_name), keystore_pass.toCharArray());
            
            return true;
        }catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public boolean importCertificate(File file, String string) {
        try {
            FileInputStream fis = new FileInputStream(file.getAbsolutePath());
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) factory.generateCertificate(fis);
            keystore.setCertificateEntry(string, cert);
            fis.close();
            FileOutputStream fos = new FileOutputStream(keystore_name);
            keystore.store(fos, keystore_pass.toCharArray());
            fos.close();
            return true;
        }catch(Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public boolean exportCertificate(File file, int i) {
        try {
            return true;
        } catch(Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public String getIssuer(String keypair) {
        try {
            KeyStore.PrivateKeyEntry k = (KeyStore.PrivateKeyEntry) keystore.getEntry(keypair, new KeyStore.PasswordProtection(keystore_pass.toCharArray()));
            String ret = ((X509Certificate) k.getCertificate()).getIssuerDN().getName();
            int a = 1;
            return ret;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public String getIssuerPublicKeyAlgorithm(String keypair) {
        try {
            KeyStore.PrivateKeyEntry k = (KeyStore.PrivateKeyEntry) keystore.getEntry(keypair, new KeyStore.PasswordProtection(keystore_pass.toCharArray()));
            return ((X509Certificate) k.getCertificate()).getPublicKey().getAlgorithm();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public int getRSAKeyLength(String string) {
        try {
            KeyStore.PrivateKeyEntry e = (KeyStore.PrivateKeyEntry) keystore.getEntry(string, new KeyStore.PasswordProtection(keystore_pass.toCharArray()));
            String algorithm = e.getPrivateKey().getAlgorithm();
            if (algorithm.equals("RSA")) {
                RSAPublicKey rpk = (RSAPublicKey) keystore.getCertificate(string).getPublicKey();
                return rpk.getModulus().bitLength();
            } else {
                return -1;
            }
        } catch(Exception e) {
            e.printStackTrace();
            return -1;
        }
    }

    @Override
    public List<String> getIssuers(String keypair) {
        try {
            List<String> i = new LinkedList<>();
            for(Object alias: Collections.list(keystore.aliases())) {
                X509Certificate cert = (X509Certificate) keystore.getCertificate(keypair);
                if (cert.getBasicConstraints() != -1 && !keypair.equals(alias.toString())) {
                    i.add(alias.toString());
                }
            }

            return i;
        } catch(Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public boolean generateCSR(String string) {
        try {
//            KeyStore.ProtectionParameter pp = new KeyStore.PasswordProtection(keystore_pass.toCharArray());
//            X509Certificate cert = (X509Certificate) keystore.getCertificate(string);
//            PublicKey publickey = cert.getPublicKey();
//            PrivateKey privatekey = (PrivateKey) keystore.getKey(string, keystore_pass.toCharArray());
//            
//            org.bouncycastle.asn1.x500.X500Name name = new org.bouncycastle.asn1.x500.X500Name(cert.getSubjectDN().getName());
//            PKCS10CertificationRequestBuilder req_builder = new JcaPKCS10CertificationRequestBuilder(name, publickey);
//            
//            JcaContentSignerBuilder builder = new JcaContentSignerBuilder(cert.getSigAlgName());
//            ContentSigner signer = builder.build(privatekey);
//            
//            org.bouncycastle.pkcs.PKCS10CertificationRequest req = req_builder.build(signer);
            
            return true;
            
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

}
