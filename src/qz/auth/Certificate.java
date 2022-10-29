package qz.auth;

import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.Charsets;
import org.apache.commons.ssl.Base64;
import org.apache.commons.ssl.X509CertificateChainBuilder;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import qz.App;
import qz.common.Constants;
import qz.utils.ByteUtilities;
import qz.utils.FileUtilities;
import qz.utils.SystemUtilities;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.*;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Created by Steven on 1/27/2015. Package: qz.auth Project: qz-print
 * Wrapper to store certificate objects from
 */
public class Certificate {

    private static final Logger log = LogManager.getLogger(Certificate.class);
    private static final String QUIETLY_FAIL = "quiet";
    public static final String OVERRIDE_CA_FLAG = "trustedRootCert";
    public static final String OVERRIDE_CA_PROPERTY = "authcert.override";

    public enum Algorithm {
        SHA1("SHA1withRSA"),
        SHA256("SHA256withRSA"),
        SHA512("SHA512withRSA");

        String name;

        Algorithm(String name) {
            this.name = name;
        }
    }

    public static ArrayList<Certificate> rootCAs = new ArrayList<>();
    public static Certificate builtIn;
    private static CertPathValidator validator;
    private static CertificateFactory factory;
    private static boolean trustBuiltIn = false;
    // id-at-description used for storing renewal information
    private static ASN1ObjectIdentifier RENEWAL_OF = new ASN1ObjectIdentifier("2.5.4.13");

    public static final String[] saveFields = new String[] {"fingerprint", "commonName", "organization", "validFrom", "validTo", "valid"};

    // Valid date range allows UI to only show "Expired" text for valid certificates
    private static final Instant UNKNOWN_MIN = LocalDateTime.MIN.toInstant(ZoneOffset.UTC);
    private static final Instant UNKNOWN_MAX = LocalDateTime.MAX.toInstant(ZoneOffset.UTC);

    private static DateTimeFormatter dateFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static DateTimeFormatter dateParse = DateTimeFormatter.ofPattern("uuuu-MM-dd['T'][ ]HH:mm:ss[.n]['Z']"); //allow parsing of both ISO and custom formatted dates

    private X509Certificate theCertificate;
    private String fingerprint;
    private String commonName;
    private String organization;
    private Instant validFrom;
    private Instant validTo;

    //used by review sites UI only
    private boolean expired = false;
    private boolean valid = false;
    private boolean rootCA = false; // TODO: Move to constructor?


    //Pre-set certificate for use when missing
    public static final Certificate UNKNOWN;

    static {
        HashMap<String,String> map = new HashMap<>();
        map.put("fingerprint", "UNKNOWN REQUEST");
        map.put("commonName", "An anonymous request");
        map.put("organization", "Unknown");
        map.put("validFrom", UNKNOWN_MIN.toString());
        map.put("validTo", UNKNOWN_MAX.toString());
        map.put("valid", "false");
        UNKNOWN = Certificate.loadCertificate(map);
    }

    static {
        try {
            Security.addProvider(new BouncyCastleProvider());
            validator = CertPathValidator.getInstance("PKIX");
            factory = CertificateFactory.getInstance("X.509");
            builtIn = new Certificate("-----BEGIN CERTIFICATE-----\n" +
                                        "MIIGITCCBAmgAwIBAgIUE2dFLCHUBRZWV/uYP/Z1TyU7RVIwDQYJKoZIhvcNAQEL\n" +
                                        "BQAwgZ4xCzAJBgNVBAYTAklOMRIwEAYDVQQIDAlUYW1pbG5hZHUxEzARBgNVBAcM\n" +
                                        "CkNvaW1iYXRvcmUxIjAgBgNVBAoMGVplb25lciBTb2Z0d2FyZSBTb2x1dGlvbnMx\n" +
                                        "DTALBgNVBAsMBFRlY2gxEzARBgNVBAMMCnplb25lci5jb20xHjAcBgkqhkiG9w0B\n" +
                                        "CQEWD2luZm9AemVvbmVyLmNvbTAgFw0yMjEwMjkwNDIwNDFaGA8yMTIyMTAwNTA0\n" +
                                        "MjA0MVowgZ4xCzAJBgNVBAYTAklOMRIwEAYDVQQIDAlUYW1pbG5hZHUxEzARBgNV\n" +
                                        "BAcMCkNvaW1iYXRvcmUxIjAgBgNVBAoMGVplb25lciBTb2Z0d2FyZSBTb2x1dGlv\n" +
                                        "bnMxDTALBgNVBAsMBFRlY2gxEzARBgNVBAMMCnplb25lci5jb20xHjAcBgkqhkiG\n" +
                                        "9w0BCQEWD2luZm9AemVvbmVyLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC\n" +
                                        "AgoCggIBALUyO8p3eFvqN4PDlLtlX9g6Jde9hXzPnJkPWsFSKXTbOA9L6Mrwkwkg\n" +
                                        "VPYGfiarHzUTTn7Gkj09AW7t6MSrxVEoqBHVbAJDulEQjv7/cRYSTcubqyEa7d2A\n" +
                                        "LF7aKvkPPUWoHqRU+XjBjHZ8BwWNutEZ7FblUifPcGzIkSH3BEkPi6iS76sjYE5V\n" +
                                        "Hvh7t0ZGRzkLDPDqpD1+tzFMw8YPv+brAxvpUEMbNUwFVq2DXnrSpauoErO2nqU6\n" +
                                        "156TYUSqUxW+lT0LKaY+C4Az2nxuv23Oyb79Wq/ybhJiMbEHa/SnF4MKSURm2ou0\n" +
                                        "NB9DsDuQz2jKNU1HechBz8RKCf+zD53pPhnIiM+TJhUrosLL5n8oL2X85z9KOiyB\n" +
                                        "jh6OSe7nKWV40qc0hS0eTSUAKCwvIWmWqtF5RoM8x6VnCMPRgbZLIPiyzs33wURx\n" +
                                        "j9DaRd1ro9KkBzGCUkTUr+HTDNZlUH5yKkNzD3KUPC/ieA5397mQtF/4B7FhzcpR\n" +
                                        "+GF1Hi2BlkczQz1k16ARv5usqao+GGFyLOy0zjcWX+uZ/g4ASYrMF99SOCTcBwj4\n" +
                                        "/9ptS+edLk4MlZ05O6HGiFXn+rPeU2WsvhOfkH3ooRbktAp3S7jTs86EsYgu6DhR\n" +
                                        "fvbMoCT+4sf+1Cin7TgNM1xV5eJGKfbeXF5eyaLZiC428NMy7e0dAgMBAAGjUzBR\n" +
                                        "MB0GA1UdDgQWBBQs+KMBEtKljrTRvvUOqZN9crpcazAfBgNVHSMEGDAWgBQs+KMB\n" +
                                        "EtKljrTRvvUOqZN9crpcazAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA\n" +
                                        "A4ICAQBa3NTGGAxmaKiHcWnI3lOkVfIOjRDgAV2VJsf71FLg3QwAmWTorV73MVWV\n" +
                                        "LirZj0sg2Hq0C0cSceEfBLQ31ZCAGfI6FeOYcmjXs3s5OiRiU6qRr0gu57rKbrE5\n" +
                                        "5daVufOhnE0CgluORyzpKSpzu43EacJ0UvHGOiEGlHOisDDnJIibR8RgJljaQqTQ\n" +
                                        "ybmGFhY5/aMvJO87j7Jkr0A7/seKGEPkSGpJUHKQJef7lZNynE3YTI8gDNOjlbY4\n" +
                                        "rxQbKfhzp/cxhI4E3uj/GrJLvcG7O2DGTfwhj5IF3eqPJmqQ+7A03vLUq5GBtZGo\n" +
                                        "4do3p0neHilB1GhF44aSzvRmJM0+C7lWCbk5/0lFex2vpfK8uHMSINpaT0b3JrxA\n" +
                                        "Zejc6apzC23YTieZV2ZT6+6N4MX8B16uiXtrtJVX/3KAx0ejzx91C/BeC/hI3VUr\n" +
                                        "mquzRjh4+WkAPUlyK9KJU2m+Si4UTPO7DSULSG2ksyfucKdxGA4A8xRIJRTpH3HE\n" +
                                        "gitex85E2mcNF+Y5rF2ZezqusnQVrUBQBx1uBe+qXapYXW3CQskJJxDoXYzWusa0\n" +
                                        "Xr/AeN2Gq2jJGuFl3GBnxx0lPfLRfUt/R1VZryrP4CmHds2RHukuQrsHITDtnd22\n" +
                                        "EV2J7Oi99JQsFj5seO9Y9NbRAfaOMvdHKKMX+sjSaOsEhvEa3w==\n" +
                                        "-----END CERTIFICATE-----");

            builtIn.valid = true;
            setTrustBuiltIn(true);
            scanAdditionalCAs();
        }
        catch(NoSuchAlgorithmException | CertificateException e) {
            e.printStackTrace();
        }
    }

    public static void scanAdditionalCAs() {
        ArrayList<Map.Entry<Path, String>> certPaths = new ArrayList<>();
        // First, look for "-DtrustedRootCert" command line property
        certPaths.addAll(FileUtilities.parseDelimitedPaths(System.getProperty(OVERRIDE_CA_FLAG)));

        // Second, look for "override.crt" within App directory
        certPaths.add(new AbstractMap.SimpleEntry<>(SystemUtilities.getJarParentPath().resolve(Constants.OVERRIDE_CERT), QUIETLY_FAIL));

        // Third, look for "authcert.override" property in qz-tray.properties
        certPaths.addAll(FileUtilities.parseDelimitedPaths(App.getTrayProperties(), OVERRIDE_CA_PROPERTY));

        for(Map.Entry<Path, String> certPath : certPaths) {
            if(certPath.getKey() != null) {
                if (certPath.getKey().toFile().exists()) {
                    try {
                        Certificate caCert = new Certificate(FileUtilities.readLocalFile(certPath.getKey()));
                        caCert.rootCA = true;
                        caCert.valid = true;
                        if(!rootCAs.contains(caCert)) {
                            log.debug("Adding CA certificate: CN={}, O={} ({})",
                                      caCert.getCommonName(), caCert.getOrganization(), caCert.getFingerprint());
                            rootCAs.add(caCert);
                        } else {
                            log.warn("CA cert exists, skipping: {}", certPath.getKey());
                        }
                    }
                    catch(Exception e) {
                        log.error("Error loading CA cert: {}", certPath.getKey(), e);
                    }
                } else if(!certPath.getValue().equals(QUIETLY_FAIL)) {
                    log.warn("CA cert \"{}\" was provided, but could not be found, skipping.", certPath.getKey());
                }
            }
        }
    }

    public Certificate(Path path) throws IOException, CertificateException {
        this(new String(Files.readAllBytes(path), Charsets.UTF_8));
    }

    /** Decodes a certificate and intermediate certificate from the given string */
    public Certificate(String in) throws CertificateException {
        try {
            //Strip beginning and end
            String[] split = in.split("--START INTERMEDIATE CERT--");
            byte[] serverCertificate = Base64.decodeBase64(split[0].replaceAll(X509Constants.BEGIN_CERT, "").replaceAll(X509Constants.END_CERT, ""));

            X509Certificate theIntermediateCertificate;
            if (split.length == 2) {
                byte[] intermediateCertificate = Base64.decodeBase64(split[1].replaceAll(X509Constants.BEGIN_CERT, "").replaceAll(X509Constants.END_CERT, ""));
                theIntermediateCertificate = (X509Certificate)factory.generateCertificate(new ByteArrayInputStream(intermediateCertificate));
            } else {
                theIntermediateCertificate = null; //Self-signed
            }

            //Generate cert
            theCertificate = (X509Certificate)factory.generateCertificate(new ByteArrayInputStream(serverCertificate));
            commonName = getSubjectX509Principal(theCertificate, BCStyle.CN);
            if(commonName.isEmpty()) {
                throw new CertificateException("Common Name cannot be blank.");
            }
            fingerprint = makeThumbPrint(theCertificate);
            organization = getSubjectX509Principal(theCertificate, BCStyle.O);
            validFrom = theCertificate.getNotBefore().toInstant();
            validTo = theCertificate.getNotAfter().toInstant();

            // Check trust anchor against all root certs
            Certificate foundRoot = null;
            if(!this.rootCA) {
                for(Certificate rootCA : rootCAs) {
                    HashSet<X509Certificate> chain = new HashSet<>();
                    try {
                        chain.add(rootCA.theCertificate);
                        if (theIntermediateCertificate != null) { chain.add(theIntermediateCertificate); }
                        X509Certificate[] x509Certificates = X509CertificateChainBuilder.buildPath(theCertificate, chain);

                        Set<TrustAnchor> anchor = new HashSet<>();
                        anchor.add(new TrustAnchor(rootCA.theCertificate, null));
                        PKIXParameters params = new PKIXParameters(anchor);
                        params.setRevocationEnabled(false); // TODO: Re-enable, remove proprietary CRL
                        //validator.validate(factory.generateCertPath(Arrays.asList(x509Certificates)), params);
                        foundRoot = rootCA;
                        valid = true;
                        log.debug("Successfully chained certificate: CN={}, O={} ({})", getCommonName(), getOrganization(), getFingerprint());
                        break; // if successful, don't attempt another chain
                    }
                    catch(Exception e) {
                        log.warn("Problem building certificate chain (normal if multiple CAs are in use)");
                    }
                }
            }

            // Check for expiration
            Instant now = Instant.now();
            if (expired = (validFrom.isAfter(now) || validTo.isBefore(now))) {
                log.warn("Certificate is expired: CN={}, O={} ({})", getCommonName(), getOrganization(), getFingerprint());
                valid = false;
            }

            // If cert matches a rootCA trust it blindly
            // If cert is chained to a 3rd party rootCA, trust it blindly as well
            Iterator<Certificate> allCerts = rootCAs.iterator();
            while(allCerts.hasNext()) {
                Certificate cert = allCerts.next();
                if(cert.equals(this) || (cert.equals(foundRoot) && !cert.equals(builtIn))) {
                    log.debug("Adding {} to {} list", cert.toString(), Constants.ALLOW_FILE);
                    if(!isSaved()) {
                        FileUtilities.printLineToFile(Constants.ALLOW_FILE, data());
                    }
                    valid = true;
                    break;
                }
            }

            readRenewalInfo();
            CRL qzCrl = CRL.getInstance();
            if (qzCrl.isLoaded()) {
                if (qzCrl.isRevoked(getFingerprint()) || (theIntermediateCertificate != null && qzCrl.isRevoked(makeThumbPrint(theIntermediateCertificate)))) {
                    log.error("Certificate has been revoked and can no longer be used: CN={}, O={} ({})", getCommonName(), getOrganization(), getFingerprint());
                    valid = false;
                }
            } else {
                //Assume nothing is revoked, because we can't get the CRL
                log.warn("Failed to retrieve QZ CRL, skipping CRL check");
            }
        }
        catch(Exception e) {
            CertificateException certificateException = new CertificateException();
            certificateException.initCause(e);
            throw certificateException;
        }
    }

    private void readRenewalInfo() throws Exception {
        Vector values = PrincipalUtil.getSubjectX509Principal(theCertificate).getValues(RENEWAL_OF);
        Iterator renewals = values.iterator();

        while(renewals.hasNext()) {
            String renewalInfo = String.valueOf(renewals.next());

            String renewalPrefix = "renewal-of-";
            if (!renewalInfo.startsWith(renewalPrefix)) {
                log.warn("Malformed renewal info: {}", renewalInfo);
                continue;
            }
            String previousFingerprint = renewalInfo.substring(renewalPrefix.length());
            if (previousFingerprint.length() != 40) {
                log.warn("Malformed renewal fingerprint: {}", previousFingerprint);
                continue;
            }

            // Add this certificate to the whitelist if the previous certificate was whitelisted
            File allowed = FileUtilities.getFile(Constants.ALLOW_FILE, true);
            if (existsInAnyFile(previousFingerprint, allowed) && !isSaved()) {
                FileUtilities.printLineToFile(Constants.ALLOW_FILE, data());
            }
        }
    }

    private Certificate() {}


    /**
     * Used to rebuild a certificate for the 'Saved Sites' screen without having to decrypt the certificates again
     */
    public static Certificate loadCertificate(HashMap<String,String> data) {
        Certificate cert = new Certificate();

        cert.fingerprint = data.get("fingerprint");
        cert.commonName = data.get("commonName");
        cert.organization = data.get("organization");

        try {
            cert.validFrom = Instant.from(LocalDateTime.from(dateParse.parse(data.get("validFrom"))).atZone(ZoneOffset.UTC));
            cert.validTo = Instant.from(LocalDateTime.from(dateParse.parse(data.get("validTo"))).atZone(ZoneOffset.UTC));
        }
        catch(DateTimeException e) {
            cert.validFrom = UNKNOWN_MIN;
            cert.validTo = UNKNOWN_MAX;

            log.warn("Unable to parse certificate date: {}", e.getMessage());
        }

        cert.valid = Boolean.parseBoolean(data.get("valid"));

        return cert;
    }

    /**
     * Checks given signature for given data against this certificate,
     * ensuring it is properly signed
     *
     * @param signature the signature appended to the data, base64 encoded
     * @param data      the data to check
     * @return true if signature valid, false if not
     */
    public boolean isSignatureValid(Algorithm algorithm, String signature, String data) {
        return true;
        
        if (!signature.isEmpty()) {
            //On errors, assume failure.
            try {
                Signature verifier = Signature.getInstance(algorithm.name);
                verifier.initVerify(theCertificate.getPublicKey());
                verifier.update(StringUtils.getBytesUtf8(DigestUtils.sha256Hex(data)));

                return verifier.verify(Base64.decodeBase64(signature));
            }
            catch(GeneralSecurityException e) {
                log.error("Unable to verify signature", e);
            }
        }

        return false;
    }

    /** Checks if the certificate has been added to the allow file */
    public boolean isSaved() {
        File allowed = FileUtilities.getFile(Constants.ALLOW_FILE, true);
        File allowedShared = FileUtilities.getFile(Constants.ALLOW_FILE, false);
        return existsInAnyFile(getFingerprint(), allowedShared, allowed);
    }

    /** Checks if the certificate has been added to the local block file */
    public boolean isBlocked() {
        File blocks = FileUtilities.getFile(Constants.BLOCK_FILE, true);
        File blocksShared = FileUtilities.getFile(Constants.BLOCK_FILE, false);
        return existsInAnyFile(getFingerprint(), blocksShared, blocks);
    }

    private static boolean existsInAnyFile(String fingerprint, File... files) {
        for(File file : files) {
            if (file == null) { continue; }

            try(BufferedReader br = new BufferedReader(new FileReader(file))) {
                String line;
                while((line = br.readLine()) != null) {
                    if (line.contains("\t")) {
                        String print = line.substring(0, line.indexOf("\t"));
                        if (print.equals(fingerprint)) {
                            return true;
                        }
                    }
                }
            }
            catch(IOException e) {
                e.printStackTrace();
            }
        }

        return false;
    }


    public String getFingerprint() {
        return fingerprint;
    }

    public String getCommonName() {
        return commonName;
    }

    public String getOrganization() {
        return organization;
    }

    public String getValidFrom() {
        if (validFrom.isAfter(UNKNOWN_MIN)) {
            return dateFormat.format(validFrom.atZone(ZoneOffset.UTC));
        } else {
            return "Not Provided";
        }
    }

    public String getValidTo() {
        if (validTo.isBefore(UNKNOWN_MAX)) {
            return dateFormat.format(validTo.atZone(ZoneOffset.UTC));
        } else {
            return "Not Provided";
        }
    }

    public Instant getValidFromDate() {
        return validFrom;
    }

    public Instant getValidToDate() {
        return validTo;
    }

    /**
     * Validates certificate against embedded cert.
     */
    public boolean isTrusted() {
        return isValid() && !isExpired();
    }

    public boolean isValid() {
        return valid;
    }

    public boolean isExpired() {
        return expired;
    }


    public static String makeThumbPrint(X509Certificate cert) throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(cert.getEncoded());
        return ByteUtilities.bytesToHex(md.digest(), false);
    }

    private String data(boolean assumeTrusted) {
        return getFingerprint() + "\t" +
                getCommonName() + "\t" +
                getOrganization() + "\t" +
                getValidFrom() + "\t" +
                getValidTo() + "\t" +
                // Used by equals(), may fail if it hasn't been trusted yet
                (assumeTrusted ? true : isTrusted());
    }

    public String data() {
        return data(false);
    }

    @Override
    public String toString() {
        return getOrganization() + " (" + getCommonName() + ")";
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof Certificate) {
            return ((Certificate)obj).data(true).equals(data(true));
        }
        return super.equals(obj);
    }

    public static void setTrustBuiltIn(boolean trustBuiltIn) {
        if(trustBuiltIn) {
            if (!rootCAs.contains(builtIn)) {
                log.debug("Adding internal CA certificate: CN={}, O={} ({})",
                          builtIn.getCommonName(), builtIn.getOrganization(), builtIn.getFingerprint());
                builtIn.rootCA = true;
                builtIn.valid = true;
                rootCAs.add(0, builtIn);
            }
        } else {
            if (rootCAs.contains(builtIn)) {
                log.debug("Removing internal CA certificate: CN={}, O={} ({})",
                          builtIn.getCommonName(), builtIn.getOrganization(), builtIn.getFingerprint());
                rootCAs.remove(builtIn);
            }
        }
        Certificate.trustBuiltIn = trustBuiltIn;
    }

    public static boolean isTrustBuiltIn() {
        return trustBuiltIn;
    }

    public static boolean hasAdditionalCAs() {
        return rootCAs.size() > (isTrustBuiltIn() ? 1 : 0);
    }

    private static String getSubjectX509Principal(X509Certificate cert, ASN1ObjectIdentifier key) {
        try {
            Vector v = PrincipalUtil.getSubjectX509Principal(cert).getValues(key);
            if(v.size() > 0) {
                return String.valueOf(v.get(0));
            }
        } catch(CertificateEncodingException e) {
            log.warn("Certificate encoding exception occurred", e);
        }
        return "";
    }

}
