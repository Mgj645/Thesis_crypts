package samples;

import tss.Helpers;
import tss.Tpm;
import tss.TpmFactory;
import tss.Tss;
import tss.tpm.*;

import java.io.Serializable;

public class sample  implements Serializable {
   private boolean usesTbs;
   private Tpm tpm;
   private TPMT_PUBLIC aesTemplate;

   private byte[] iv;

    public static byte[] nullVec = new byte[0];

    public sample()
    {
        usesTbs = CmdLine.isOptionPresent("tbs", "t");
        System.out.println("Connecting to " + (usesTbs ? "OS TPM" : "TPM Simulator"));
        tpm = usesTbs ? TpmFactory.platformTpm() : TpmFactory.localTpmSimulator();

        aesTemplate = new TPMT_PUBLIC(TPM_ALG_ID.SHA256,
                new TPMA_OBJECT(TPMA_OBJECT.decrypt, TPMA_OBJECT.sign, TPMA_OBJECT.fixedParent, TPMA_OBJECT.fixedTPM,
                        TPMA_OBJECT.userWithAuth),
                new byte[0],
                new TPMS_SYMCIPHER_PARMS(new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES,  128, TPM_ALG_ID.CFB)),
                new TPM2B_DIGEST_Symcipher());
        }



    public byte[] encrypt(byte[] toEncrypt, byte[] key){
        // The key is passed in in the SENSITIVE_CREATE structure
        TPMS_SENSITIVE_CREATE sensCreate = new TPMS_SENSITIVE_CREATE(nullVec, key);

        // "Create" they key based on the externally provided keying data
        CreatePrimaryResponse aesPrimary = tpm.CreatePrimary(tpm._OwnerHandle, sensCreate, aesTemplate, nullVec,
                new TPMS_PCR_SELECTION[0]);
        TPM_HANDLE aesHandle = aesPrimary.handle;


        iv = new byte[16];

       byte[] result =  tpm.EncryptDecrypt(aesHandle, (byte) 0, TPM_ALG_ID.CFB, iv, toEncrypt).outData;

       tpm.FlushContext(aesHandle);

       return result;
    }

    public byte[] decrypt(byte[] encrypted, byte[] key){
        System.out.println(Helpers.toHex(key));

        TPMS_SENSITIVE_CREATE sensCreate = new TPMS_SENSITIVE_CREATE(nullVec, key);

        CreatePrimaryResponse aesPrimary = tpm.CreatePrimary(tpm._OwnerHandle, sensCreate, aesTemplate, nullVec,
                new TPMS_PCR_SELECTION[0]);
        TPM_HANDLE aesHandle = aesPrimary.handle;

        byte[] result = tpm.EncryptDecrypt(aesHandle, (byte) 1, TPM_ALG_ID.CFB, iv,
                encrypted).outData;

        tpm.FlushContext(aesHandle);

        return result;

    }

    public byte[] getIV(){
        return iv;
    }

    public void setIV(byte[] iv){
        this.iv = iv;
    }

    public String hmac(TPM_ALG_ID hashAlg, byte[] toHash, byte[] key) {

        // TPM HMAC needs a key loaded into the TPM.
        // Key and data to be HMACd


        TPMT_PUBLIC hmacTemplate = new TPMT_PUBLIC(hashAlg,
                new TPMA_OBJECT(TPMA_OBJECT.sign, TPMA_OBJECT.fixedParent, TPMA_OBJECT.fixedTPM, TPMA_OBJECT.userWithAuth),
                new byte[0], new TPMS_KEYEDHASH_PARMS(new TPMS_SCHEME_HMAC(hashAlg)),
                new TPM2B_DIGEST_Keyedhash(new byte[0]));

        // The key is passed in in the SENSITIVE_CREATE structure

        TPMS_SENSITIVE_CREATE sensCreate = new TPMS_SENSITIVE_CREATE(nullVec, key);

        // "Create" they key based on the externally provided keying data
        CreatePrimaryResponse hmacPrimary = tpm.CreatePrimary(tpm._OwnerHandle, sensCreate, hmacTemplate, nullVec,
                new TPMS_PCR_SELECTION[0]);

        TPM_HANDLE keyHandle = hmacPrimary.handle;
        // There are three ways for the TPM to HMAC. The HMAC command, an HMAC
        // sequence, or TPM2_Sign()

        byte[] hmac1 = tpm.HMAC(keyHandle, toHash, hashAlg);

        tpm.FlushContext (keyHandle);
        return toHex2(hmac1);
    }

    void write(String s) {
        System.out.println(s);
    }

    public static String toHex2(byte[] x)
    {
        StringBuilder sb = new StringBuilder(x.length * 2);
        for (byte b: x)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }


    Tss.ActivationCredential bundle;
    CreatePrimaryResponse rsaEk;

    public void ek(byte[] activationData) {


            // Note: this sample allows userWithAuth - a "standard" EK does not (see
            // the other EK sample)



             rsaEk = tpm.CreatePrimary(TPM_HANDLE.from(TPM_RH.OWNER),
                    new TPMS_SENSITIVE_CREATE(), new TPMT_PUBLIC(TPM_ALG_ID.SHA256,
                             new TPMA_OBJECT(TPMA_OBJECT.fixedTPM, TPMA_OBJECT.fixedParent, TPMA_OBJECT.sensitiveDataOrigin,
                                     TPMA_OBJECT.userWithAuth,
                                     /* TPMA_OBJECT.adminWithPolicy, */ TPMA_OBJECT.restricted, TPMA_OBJECT.decrypt),
                             new byte[] { (byte) 0x83, 0x71, (byte) 0x97, 0x67, 0x44, (byte) 0x84, (byte) 0xb3,
                                     (byte) 0xf8, 0x1a, (byte) 0x90, (byte) 0xcc, (byte) 0x8d, 0x46, (byte) 0xa5, (byte) 0xd7, 0x24,
                                     (byte) 0xfd, 0x52, (byte) 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, (byte) 0xf2, (byte) 0xa1, (byte) 0xda,
                                     0x1b, 0x33, 0x14, 0x69, (byte) 0xaa },
                             new TPMS_RSA_PARMS(new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES,  128, TPM_ALG_ID.CFB),
                                     new TPMS_NULL_ASYM_SCHEME(),  2048, 0),
                             new TPM2B_PUBLIC_KEY_RSA()), new byte[0], new TPMS_PCR_SELECTION[0]);



            // Use tss.java to create an activation credential
             bundle = Tss.createActivationCredential(rsaEk.outPublic,
                    rsaEk.name, activationData);

            byte[] recoveredSecret = tpm.ActivateCredential(rsaEk.handle, rsaEk.handle, bundle.CredentialBlob, bundle.Secret);

        byte[] recoveredSecret2 = tpm.ActivateCredential(rsaEk.handle, rsaEk.handle, bundle.CredentialBlob, bundle.Secret);


        System.out.println("Activation in:        " + Helpers.toHex(activationData));
            System.out.println("Activation recovered: " + Helpers.toHex(recoveredSecret));
        System.out.println("Activation recovered: " + Helpers.toHex(recoveredSecret2));

            return;
        }


    public byte[] getKey(){
       return tpm.ActivateCredential(rsaEk.handle, rsaEk.handle, bundle.CredentialBlob, bundle.Secret);
    }



}
