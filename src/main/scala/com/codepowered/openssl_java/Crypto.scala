package com.codepowered.openssl_java

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo

import java.io.{File, FileInputStream, FileOutputStream}
import java.nio.charset.Charset
import java.security.interfaces.{RSAPrivateKey, RSAPublicKey}
import java.security.spec.{PKCS8EncodedKeySpec, X509EncodedKeySpec}
import java.security.{KeyFactory, KeyPair, KeyPairGenerator}
import java.util.Base64
import scala.collection.mutable.ArrayBuffer


class Crypto(bits: Int) {

  val dash5 = "-----"
  val eol = "\n"
  val lineLength = 64
  val charset: Charset = Charset.forName("ASCII")
  val begin: String = dash5 + "BEGIN "
  val end: String = dash5 + "END "

  def pem(title: String, bytes: Array[Byte]): String = {
    val s = (s"${dash5}BEGIN $title$dash5" +: (breakBase64(Base64.getEncoder.encode(bytes)) :+ s"${dash5}END $title$dash5")).mkString(eol)
    if (s.isEmpty) s else s"$s$eol"
  }

  def generateKeyPair(): KeyPair = {
    val keyPairGen = KeyPairGenerator.getInstance("RSA")
    keyPairGen.initialize(bits)
    keyPairGen.generateKeyPair
  }

  def generatePrivateKey(): RSAPrivateKey = {
    generateKeyPair().getPrivate.asInstanceOf[RSAPrivateKey]
  }

  def getPublicKey(key: RSAPrivateKey): RSAPublicKey = ???

  def pkcs8(key: RSAPrivateKey): String = {
    pem("PRIVATE KEY", PrivateKeyInfo.getInstance(key.getEncoded).getEncoded)
  }

  def pkcs1(key: RSAPrivateKey): String = {
    pem("RSA PRIVATE KEY", PrivateKeyInfo.getInstance(key.getEncoded).parsePrivateKey.toASN1Primitive.getEncoded)
  }

  def pkcs8(key: RSAPublicKey): String = {
    pem("PUBLIC KEY", ???)
  }

  def pkcs1(key: RSAPublicKey): String = {
    pem("RSA PUBLIC KEY", ???)
  }

  def write(data: String, file: File): Unit = {
    val f = new FileOutputStream(file)
    try {
      f.write(data.getBytes(charset))
      f.flush()
    } finally {
      f.close()
    }
  }

  def breakBase64(bytes: Array[Byte], lineLength: Int = lineLength): Seq[String] =
    (0 to bytes.length / lineLength)
      .map(i => new String(bytes, i * lineLength, Seq(lineLength, bytes.length - i * lineLength).min, charset))
      .filter(_.nonEmpty)

  def read(file: File): String = {
    val f = new FileInputStream(file)
    try {
      new String(Stream.from(0).map { _ =>
        val b = new Array[Byte](4096)
        f.read(b) match {
          case -1 | 0 => new Array[Byte](0)
          case r if r < b.length => b.slice(0, r)
          case _ => b
        }
      }.takeWhile(_.length > 0).foldLeft(new ArrayBuffer[Byte])(_ ++ _).toArray, charset)
    } finally {
      f.close()
    }
  }

  def loadPem(file: File): (String, Array[Byte]) = {
    val s = read(file).trim
    val t = Option(s)
      .filter(_.startsWith(begin))
      .map(_.substring(begin.length).split(eol, 2).head.trim)
      .filter(_.endsWith(dash5))
      .map(t => t.substring(0, t.length - dash5.length))
      .filter(_.nonEmpty)
    t.zip(t
      .filter(t => s.endsWith(s"$eol$end$t$dash5"))
      .map(t => Base64.getDecoder.decode(s.substring(s"$begin$t$dash5".length, s.length - s"$end$t$dash5".length).split(eol).map(_.trim).mkString("")))
    ).head
  }

  def loadPrivatePkcs8(encoded: Array[Byte]): RSAPrivateKey = {
    val keyFactory = KeyFactory.getInstance("RSA")
    val keySpec = new PKCS8EncodedKeySpec(encoded)
    keyFactory.generatePrivate(keySpec).asInstanceOf[RSAPrivateKey]
  }

  def loadPublicPkcs8(encoded: Array[Byte]): RSAPublicKey = {
    val kf = KeyFactory.getInstance("RSA")
    kf.generatePublic(new X509EncodedKeySpec(encoded)).asInstanceOf[RSAPublicKey]
  }

  def loadPublicRsa(encoded: Array[Byte]) = ???

  /**
   * https://stackoverflow.com/questions/7216969/getting-rsa-private-key-from-pem-base64-encoded-private-key-file/55339208#55339208
   */
  def loadPrivateRsa(pkcs1Bytes: Array[Byte]): RSAPrivateKey = {
    val pkcs1Length = pkcs1Bytes.length
    val totalLength = pkcs1Length + 22
    val pkcs8Header = Array[Byte](0x30, 0x82.toByte, ((totalLength >> 8) & 0xff).toByte, (totalLength & 0xff).toByte, // Sequence + total length
      0x2, 0x1, 0x0, // Integer (0)
      0x30, 0xD, 0x6, 0x9, 0x2A, 0x86.toByte, 0x48, 0x86.toByte, 0xF7.toByte, 0xD, 0x1, 0x1, 0x1, 0x5, 0x0, // Sequence: 1.2.840.113549.1.1.1, NULL
      0x4, 0x82.toByte, ((pkcs1Length >> 8) & 0xff).toByte, (pkcs1Length & 0xff).toByte) // Octet string + length
    val pkcs8bytes = join(pkcs8Header, pkcs1Bytes)
    loadPrivatePkcs8(pkcs8bytes)
  }

  /**
   * https://stackoverflow.com/questions/7216969/getting-rsa-private-key-from-pem-base64-encoded-private-key-file/55339208#55339208
   */
  private def join(byteArray1: Array[Byte], byteArray2: Array[Byte]) = {
    val bytes = new Array[Byte](byteArray1.length + byteArray2.length)
    System.arraycopy(byteArray1, 0, bytes, 0, byteArray1.length)
    System.arraycopy(byteArray2, 0, bytes, byteArray1.length, byteArray2.length)
    bytes
  }

  def loadKey(source: File): Either[RSAPrivateKey, RSAPublicKey] = {
    val (t, b64String) = loadPem(source)
    t match {
      case "PRIVATE KEY" => Left(loadPrivatePkcs8(b64String))
      case "PUBLIC KEY" => Right(loadPublicPkcs8(b64String))
      case "RSA PRIVATE KEY" => Left(loadPrivateRsa(b64String))
      case "RSA PUBLIC KEY" => Right(loadPublicRsa(b64String))
    }
  }

}
