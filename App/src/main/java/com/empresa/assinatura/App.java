package com.empresa.assinatura;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Enumeration;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;

public class App {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        String src = "src/main/resources/documento.pdf";
        String dest = "src/main/resources/documento_assinado.pdf";
        String keystore = "src/main/resources/keystore.jks";
        char[] password = "senhaKevin".toCharArray();

        // Carrega o KeyStore
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(keystore), password);

        // Obtém a chave privada e o certificado
        Enumeration<String> aliases = ks.aliases();
        String alias = aliases.nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, password);
        Certificate[] chain = ks.getCertificateChain(alias);

        // Cria o PdfSigner
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());

        // Configura a aparência da assinatura
        Rectangle rect = new Rectangle(36, 648, 200, 100); // Ajuste a posição e o tamanho conforme necessário
        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance.setReason("Assinatura Digital")
                  .setLocation("Localização")
                  .setPageRect(rect)
                  .setPageNumber(1)
                  .setSignatureCreator("sig");
        signer.setFieldName("sig");

        // Configura a assinatura DSA
        IExternalSignature pks = new PrivateKeySignature(pk, "SHA256", "BC");
        IExternalDigest digest = new BouncyCastleDigest();

        // Assina o documento
        signer.signDetached(digest, pks, chain, null, null, null, 0, PdfSigner.CryptoStandard.CADES);
    }
}
