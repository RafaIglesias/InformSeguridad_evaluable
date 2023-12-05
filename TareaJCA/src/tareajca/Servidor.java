/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tareajca;

import java.net.*;  
import java.io.*; 
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author samuelmp
 */
public class Servidor {

    public static void main(String args[]) throws IOException, ClassNotFoundException, CertificateEncodingException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, InvalidKeyException, SignatureException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException{
    
        Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 1);
        
        //Objetos para la creacion y utilizacion del socket
        ServerSocket ss=new ServerSocket(9876);  
        Socket s=ss.accept();  
        DataInputStream din=new DataInputStream(s.getInputStream());  
        DataOutputStream dout=new DataOutputStream(s.getOutputStream());  
        BufferedReader br=new BufferedReader(new InputStreamReader(System.in));  
        
        //Leer certificado desde el keystore
        X509Certificate x509cert = cargar_certificado_digital_de_almacen();
        
        //El servidor envía el certificado al cliente a través del socket
        byte[] bytes_Cert = x509cert.getEncoded();   
        enviar_bytes(bytes_Cert, dout);
        
        //El servidor espera la clave de sesion encriptada
        byte[] mensaje = recibir_bytes(din);
        
        //Servidor carga la clave privada
        PrivateKey clavePrivada = cargar_clave_privada_de_almacen();
        
        //Servidor desencripta la clave de sesion con su clave privada           
        SecretKey claveSesion = desencriptar_con_clave_privada(mensaje,clavePrivada);
        
        
        //COMIENZA LA COMUNICACION ENCRIPTADA --------------------------------------
        //Servidor envia confirmacion encriptando con la clave de sesion
        mensaje = "clave de sesion recibida OK".getBytes();
        byte[] mensaje_cifrado = encriptar_mensaje(mensaje, claveSesion);
        enviar_bytes(mensaje_cifrado, dout);
                
        //Servidor carga documento pdf
        Path pdfPath = Paths.get("documento.pdf");
        byte[] pdf_bytes = Files.readAllBytes(pdfPath);
        
        //Cifra el pdf con la clave de sesion y la envia
        mensaje_cifrado = encriptar_mensaje(pdf_bytes, claveSesion);
        enviar_bytes(mensaje_cifrado, dout);
        
        //Crea el hash del pdf
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(pdf_bytes);
        byte[] digest = md.digest();
                     
        //Firma el hash
        byte[] datosFirmados = firmar_datos(digest,clavePrivada);
        
        //Encripta la firma con la clave de sesion y la envia
        mensaje_cifrado = encriptar_mensaje(datosFirmados, claveSesion);
        enviar_bytes(mensaje_cifrado, dout);
                                               
        din.close();  
        dout.close(); 
        s.close();  
        ss.close();  
    }
   
    
    private static X509Certificate cargar_certificado_digital_de_almacen() throws FileNotFoundException, 
        KeyStoreException, IOException, NoSuchAlgorithmException, 
        CertificateException, UnrecoverableKeyException{
        //COMPLETAR....
        //tengo que cargar el certificado, que guarda tambien las claves publico privada
        //saco mi objeto de tipo certificado , que creo con la linea de comandos antes .
        String alias = "miCert";
        String keypass = "rafaeliglesias";
        
        //tengo que crear con el keytool en linea de comandos mi certificado aqui , para poder acceder a el desde estos comandos
        FileInputStream input = new FileInputStream("almacenClaves");
        KeyStore almacen = KeyStore.getInstance(KeyStore.getDefaultType());
        
         almacen.load(input,keypass.toCharArray());
         
         X509Certificate certificado = (X509Certificate) almacen.getCertificate(alias);
        return certificado;
        
       
        
 
    }
    
    private static PrivateKey cargar_clave_privada_de_almacen() throws FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException{
          //COMPLETAR....
          
     //tengo que del objeto keystore cargar mi clave privada .
     
          
          
        String alias = "miCert";
        String keypass = "rafaeliglesias";
        
        //tengo que crear con el keytool en linea de comandos mi certificado aqui , para poder acceder a el desde estos comandos
        FileInputStream input = new FileInputStream("almacenClaves");
        KeyStore almacen = KeyStore.getInstance(KeyStore.getDefaultType());
        
         almacen.load(input,keypass.toCharArray());
         
          PrivateKey claveprivada = (PrivateKey) almacen.getKey(alias, keypass.toCharArray());
          
          return claveprivada;
          
    }
    
    private static byte[] firmar_datos(byte[] datosParaFirmar,PrivateKey clavePrivada) throws FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, InvalidKeyException, SignatureException{           
          //COMPLETAR....
          //tengo que firmar los datos con mi clave privada 
          //creo que sería oportuno pasar la clave privada como argumento a la funcion.
          
          
          //en su ejemplo usa solo RSA, quizas peta  por md5withrsa
          
          
          Signature firma = Signature.getInstance("MD5WithRSA");
          firma.initSign(clavePrivada);
          firma.update(datosParaFirmar);
          return firma.sign();
          
        
    }
    
    private static byte[] encriptar_mensaje(byte[] mensaje, SecretKey claveSesion) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        //COMPLETAR....
        //encripta una informacion en bytes con la clave simetrica blowfish
        
        Cipher c = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
       c.init(Cipher.ENCRYPT_MODE, claveSesion);
       return c.doFinal(mensaje);
        
        
    }
    
    private static SecretKey desencriptar_con_clave_privada(byte[] mensaje, PrivateKey clavePrivada) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        //COMPLETAR....
        //Recibo el la clave simetrica de sesion tipo Blowfish , encriptada con mi clave publica
        //previamente compartida mediante el envio del certificado.
        //para desencriptarla uso mi clave privada.
        
        
        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.DECRYPT_MODE, clavePrivada);
        byte[] claveenbytes = c.doFinal(mensaje);
        SecretKey clavereconstruida = new SecretKeySpec(claveenbytes, "Blowfish/ECB/PKCS5Padding");
        return clavereconstruida;
        
    }
    
    private static void enviar_bytes(byte[] bytes, DataOutputStream dout) throws IOException{
        dout.writeInt(bytes.length);
        dout.write(bytes);          
        dout.flush();  
    }
    
    private static byte[] recibir_bytes(DataInputStream din) throws IOException{
        int length = din.readInt();                    
        if(length>0) {
            byte[] message = new byte[length];
            din.readFully(message, 0, message.length); 
            return message;
        }
        else
            return null;
    }
    
}
