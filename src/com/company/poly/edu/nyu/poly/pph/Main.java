/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.company.poly.edu.nyu.poly.pph;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author gholami
 */
public class Main {

  private static final String proprtyFile = "pph.properties";

  public static void main(String[] args) throws NoSuchAlgorithmException,
          Exception {

    PolyPasswordHasher pph;
    try {
      pph = new PolyPasswordHasher(proprtyFile);

      // create admin accounts  
      pph.register("admin", "correct horse");
      
      pph.register("root", "battery staple");

      // creatre user accounts
      pph.register("dennis", "menace");
      
      pph.register("eve", "iamevil");

      System.out.println("alic kitten " + pph.login("alice", "kitten"));
      
      System.out.println("alic bob " + pph.login("alice", "bob"));

      System.out.println("admin correct horse " + pph.login("admin",
              "correct horse"));
      
      System.out.println("admin admin " + pph.login("admin", "admin"));

      System.out.println("denis password " + pph.login("dennis",
              "password"));
      
      System.out.println("denis menace " + pph.login("dennis", "menace"));

      System.out.println("eve password " + pph.login("eve", "password"));

      System.out.println("eve iamevil " + pph.login("eve", "iamevil"));

    } catch (UnsupportedEncodingException | InvalidKeyException |
            IllegalBlockSizeException | InvalidAlgorithmParameterException |
            NoSuchPaddingException | BadPaddingException ex) {
      Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
    }

  }

}
