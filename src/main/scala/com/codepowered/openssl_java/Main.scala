package com.codepowered.openssl_java

import java.io.File
import java.security.interfaces.{RSAPrivateKey, RSAPublicKey}
import javax.crypto.Cipher


object Main extends App {

  val c = new Crypto(2048)
  val pair = c.generateKeyPair()
  val key = pair.getPrivate.asInstanceOf[RSAPrivateKey]
  val pub = pair.getPublic.asInstanceOf[RSAPublicKey]
  //  c.write(c.pkcs1(key), new File("generated/x1"))
  //  c.write(c.pkcs8(key), new File("generated/x8"))
  //  c.write(c.pkcs1(pub), new File("generated/x1.pub"))
  //  c.write(c.pkcs8(pub), new File("generated/x8.pub"))

  // you can also generate pub keys files by running:
  // openssl rsa -in generated/x1 -pubout > generated/x8.pub

  val encryptCipher = Cipher.getInstance("RSA")

  val key2 = c.loadKey(new File("generated/x8")) match {
    case Left(privateKey) => privateKey
  }

  val pub2 = c.loadKey(new File("generated/x8.pub")) match {
    case Right(pubKey) => pubKey
  }

  val data = Array[Byte](1, 2, 33, 4)
  println("data sz: " + data.length)

  encryptCipher.init(Cipher.ENCRYPT_MODE, pub2)
  val encrypted = encryptCipher.doFinal(data)
  println("encrypted sz: " + encrypted.length)

  val decryptCipher = Cipher.getInstance("RSA")
  decryptCipher.init(Cipher.DECRYPT_MODE, key2)
  val decrypted = decryptCipher.doFinal(encrypted)
  println("decrypted sz: " + decrypted.length)

  decrypted.foreach(println)
}
