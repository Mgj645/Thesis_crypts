package samples;

import tss.Helpers;
import tss.Tpm;
import tss.TpmFactory;
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
}
