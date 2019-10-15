package me.zozfabio.xmlsigner;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import reactor.core.publisher.Mono;

import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.MediaType.APPLICATION_XML;
import static org.springframework.http.MediaType.TEXT_PLAIN;
import static org.springframework.web.reactive.function.BodyInserters.fromObject;
import static org.springframework.web.reactive.function.server.RequestPredicates.accept;
import static org.springframework.web.reactive.function.server.RouterFunctions.route;
import static org.springframework.web.reactive.function.server.ServerResponse.badRequest;
import static org.springframework.web.reactive.function.server.ServerResponse.ok;
import static org.springframework.web.reactive.function.server.ServerResponse.status;

@SpringBootApplication
public class Application {

    private static ApplicationContext ctx;

    private static Mono<ServerResponse> sign(ServerRequest request) {
        return request.bodyToMono(String.class)
            .flatMap(xml -> {
                try {
                    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

                    Reference ref = fac.newReference("", fac.newDigestMethod(DigestMethod.SHA1, null), Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)), null, null);

                    SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null), fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null), Collections.singletonList(ref));

                    KeyStore ks = KeyStore.getInstance("JKS");
                    ks.load(ctx.getResource("classpath:keystore.jks").getInputStream(), "changeit".toCharArray());
                    KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry("1000559166", new KeyStore.PasswordProtection("changeit".toCharArray()));
                    X509Certificate cert = (X509Certificate) keyEntry.getCertificate();

                    KeyInfoFactory kif = fac.getKeyInfoFactory();
                    List<Object> x509Content = new ArrayList<>();
                    x509Content.add(cert.getSubjectX500Principal()
                        .getName());
                    x509Content.add(cert);
                    X509Data xd = kif.newX509Data(x509Content);
                    KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

                    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                    dbf.setNamespaceAware(true);
                    Document doc = dbf.newDocumentBuilder()
                        .parse(new ByteArrayInputStream(xml.getBytes()));

                    DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), doc.getDocumentElement());

                    XMLSignature signature = fac.newXMLSignature(si, ki);

                    signature.sign(dsc);

                    ByteArrayOutputStream os = new ByteArrayOutputStream();
                    TransformerFactory.newInstance()
                        .newTransformer()
                        .transform(new DOMSource(doc), new StreamResult(os));

                    return ok()
                        .contentType(APPLICATION_XML)
                        .body(fromObject(os.toString()));
                } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | KeyStoreException | IOException | CertificateException | UnrecoverableEntryException | ParserConfigurationException | SAXException | MarshalException | XMLSignatureException | TransformerException ex) {
                    ex.printStackTrace();
                    return status(INTERNAL_SERVER_ERROR)
                        .contentType(TEXT_PLAIN)
                        .body(fromObject(ex.getMessage()));
                }
            });
    }

    private static Mono<ServerResponse> verify(ServerRequest request) {
        return request.bodyToMono(String.class)
            .flatMap(xml -> {
                try {
                    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

                    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                    dbf.setNamespaceAware(true);
                    Document doc = dbf.newDocumentBuilder()
                        .parse(new ByteArrayInputStream(xml.getBytes()));

                    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
                    if (nl.getLength() == 0) {
                        return badRequest()
                            .contentType(TEXT_PLAIN)
                            .body(fromObject("Cannot find Signature element"));
                    }

                    ((Element)doc.getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#", "SignedProperties").item(0))
                        .setIdAttribute("Id", true);

                    DOMValidateContext valContext = new DOMValidateContext(new X509KeySelector(), nl.item(0));

                    XMLSignature signature = fac.unmarshalXMLSignature(valContext);

                    if (signature.validate(valContext)) {
                        return ok()
                            .contentType(TEXT_PLAIN)
                            .body(fromObject("SIGNATURE OK"));
                    }
                    return badRequest()
                        .contentType(TEXT_PLAIN)
                        .body(fromObject("SIGNATURE ERROR"));
                } catch (IOException | XMLSignatureException | ParserConfigurationException | SAXException | MarshalException ex) {
                    ex.printStackTrace();
                    return status(INTERNAL_SERVER_ERROR)
                        .contentType(TEXT_PLAIN)
                        .body(fromObject(ex.getMessage()));
                }
            });
    }

    public static void main(String[] args) {
        ctx = new SpringApplicationBuilder().sources(Application.class)
            .initializers((ApplicationContextInitializer<GenericApplicationContext>) ctx ->
                ctx.registerBean(RouterFunction.class, () ->
                    route()
                        .POST("/sign", accept(APPLICATION_XML), Application::sign)
                        .POST("/verify", accept(APPLICATION_XML), Application::verify)
                .build()))
            .run(args);
    }
}
