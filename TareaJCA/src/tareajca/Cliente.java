/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tareajca;

import java.net.*;  
import java.io.*; 
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 *
 * @author samuelmp
 */
public class Cliente {
    
  

    public static void main(String[] args) throws UnknownHostException, IOException, ClassNotFoundException, InterruptedException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
       
        Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 1);
        Socket s=new Socket("localhost",9876);  
        DataInputStream din=new DataInputStream(s.getInputStream());  
        DataOutputStream dout=new DataOutputStream(s.getOutputStream());  
        X509Certificate certificado = null;

        //Cliente espera los bytes del certificado digital
        byte[] mensaje = recibir_bytes(din);
        //Convierte los bytes a certificado
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(mensaje);
        certificado = (X509Certificate)certFactory.generateCertificate(in);

        //Cliente crea la clave de sesion
        SecretKey claveSesion = crear_clave_sesion();

        //Encripta la clave de sesion con la clave publica del servidor
        byte[] claveEncriptada = encriptar_con_clave_publica(claveSesion, certificado);

        //Cliente envia clave de sesion encriptada
        enviar_bytes(claveEncriptada, dout);

        //COMIENZA LA COMUNICACION ENCRIPTADA
        //Cliente espera confirmacion encriptada con la clave de sesion.
        mensaje = recibir_bytes(din);
        byte[] mensaje_desencriptado = desencriptar_mensaje(mensaje, claveSesion);
        System.out.println("Cliente - recibido mensaje: " + new String(mensaje_desencriptado, "UTF-8") + "\n");
                                                      
        //Cliente recibe pdf
        System.out.println("Cliente: esperando pdf");

        //Recibe el pdf
        mensaje = recibir_bytes(din);
        byte[] pdf_bytes = desencriptar_mensaje(mensaje,claveSesion);

        //Calcular el hash del pdf        
        byte[] digest = calcular_digest(pdf_bytes);

        System.out.println("Cliente: esperando firma");

        mensaje = recibir_bytes(din);
        byte[] datosFirmados = desencriptar_mensaje(mensaje,claveSesion);

        //El cliente verifica la firma
        //COMPLETAR....
        //tengo que comprobar que la firma que me envia el servidor , que esta firmada por su clave privada
        //da lo mismo que la firma con la clave publica , los comparo los digest si son iguales 
        //queda verificado
        
        
        
        //el cliente verifica la firma sobre el hash de los datos del pdf , no firma el pdf
        
        //en su ejemplo usa RSA solo
        
        //para su ejemplo no le pasa el certificado.getPublicKey , sino que el certificado entero
        Signature firma = Signature.getInstance("MD5WithRSA");
        firma.initVerify(certificado.getPublicKey());
        firma.update(digest);
        boolean firmaok = firma.verify(datosFirmados);
        if(firmaok) System.out.println("Cliente: firma correcta");
        else System.out.println("Cliente: firma incorrecta");
                            
          
        dout.close();  
        din.close(); 
        s.close();  
    }
    
    private static SecretKey crear_clave_sesion() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
       //COMPLETAR....
       //para la clave de sesion voy a utilizar el algoritmo simetrico blowfish
       
        return KeyGenerator.getInstance("Blowfish").generateKey();
        
    }
    
    private static byte[] encriptar_con_clave_publica(SecretKey claveSesion, X509Certificate certificado) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
       //COMPLETAR....
       //encripto la clave de sesion simetrica , con la clave publica del servidor obtenida en el certificado.
       
       //tengo que sacar del certificado la clave publica y eso es lo que tengo que encriptar

        Cipher c = Cipher.getInstance("RSA");
       c.init(Cipher.ENCRYPT_MODE, certificado.getPublicKey());
       
       return c.doFinal(claveSesion.getEncoded());
        
    }
    
    private static byte[] calcular_digest(byte[] datos) throws NoSuchAlgorithmException{
        //COMPLETAR....
        
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(datos);
        return md.digest();
        
        
    }
    
    private static byte[] encriptar_mensaje(byte[] mensaje, SecretKey claveSesion) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
       //COMPLETAR....
       
       //encripto el mensaje con la clave simetrica
       
        Cipher c = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
       c.init(Cipher.ENCRYPT_MODE, claveSesion);
       return c.doFinal(mensaje);
        
    }
    
    private static byte[] desencriptar_mensaje(byte[] mensaje, SecretKey claveSesion) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
       //COMPLETAR....
//desencriptar mensaje con clave de sesion

        Cipher c= Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, claveSesion);
        return c.doFinal(mensaje);
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
    
    private static void enviar_bytes(byte[] bytes, DataOutputStream dout) throws IOException{
        dout.writeInt(bytes.length);
        dout.write(bytes);          
        dout.flush();  
    }
        
}
