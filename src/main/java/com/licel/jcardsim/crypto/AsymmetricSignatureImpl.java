/*
 * Copyright 2011 Licel LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.licel.jcardsim.crypto;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.Signature;
import javacard.security.SignatureMessageRecovery;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.SignerWithRecovery;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.ISO9796d2Signer;
import org.bouncycastle.crypto.signers.RSADigestSigner;

import java.lang.reflect.Field;

/*
 * Implementation <code>Signature</code> with asymmetric keys based
 * on BouncyCastle CryptoAPI.
 * @see Signature
 */
public class AsymmetricSignatureImpl extends Signature implements SignatureMessageRecovery{

    Signer engine;
    NullableDigest digest;
    Key key;
    byte algorithm;
    boolean isInitialized;
    boolean isRecovery;
    byte[] preSig;

    public AsymmetricSignatureImpl(byte algorithm) {
        this.algorithm = algorithm;
        isRecovery = false;
        switch (algorithm) {
            case ALG_RSA_SHA_ISO9796:
                digest = new NullableDigest(new SHA1Digest());
                engine = new ISO9796d2Signer(new RSAEngine(), digest);
                break;
            case ALG_RSA_SHA_ISO9796_MR:
                digest = new NullableDigest(new SHA1Digest());
                engine = new ISO9796d2Signer(new RSAEngine(), digest);
                isRecovery = true;
                break;
            case ALG_RSA_SHA_PKCS1:
                digest = new NullableDigest(new SHA1Digest());
                engine = new RSADigestSigner(digest);
                break;
            case ALG_RSA_SHA_224_PKCS1:
                digest = new NullableDigest(new SHA224Digest());
                engine = new RSADigestSigner(digest);
                break;
            case ALG_RSA_SHA_256_PKCS1:
                digest = new NullableDigest(new SHA256Digest());
                engine = new RSADigestSigner(digest);
                break;
            case ALG_RSA_SHA_384_PKCS1:
                digest = new NullableDigest(new SHA384Digest());
                engine = new RSADigestSigner(digest);
                break;
            case ALG_RSA_SHA_512_PKCS1:
                digest = new NullableDigest(new SHA512Digest());
                engine = new RSADigestSigner(digest);
                break;
            case ALG_RSA_MD5_PKCS1:
                digest = new NullableDigest(new MD5Digest());
                engine = new RSADigestSigner(digest);
                break;
            case ALG_RSA_RIPEMD160_ISO9796:
                digest = new NullableDigest(new RIPEMD160Digest());
                engine = new ISO9796d2Signer(new RSAEngine(), digest);
                break;
            case ALG_RSA_RIPEMD160_PKCS1:
                digest = new NullableDigest(new RIPEMD160Digest());
                engine = new RSADigestSigner(digest);
                break;
            case ALG_ECDSA_SHA:
                digest = new NullableDigest(new SHA1Digest());
                engine = new DSADigestSigner(new ECDSASigner(), digest);
                break;
            case ALG_ECDSA_SHA_224:
                digest = new NullableDigest(new SHA224Digest());
                engine = new DSADigestSigner(new ECDSASigner(), digest);
                break;
            case ALG_ECDSA_SHA_256:
                digest = new NullableDigest(new SHA256Digest());
                engine = new DSADigestSigner(new ECDSASigner(), digest);
                break;
            case ALG_ECDSA_SHA_384:
                digest = new NullableDigest(new SHA384Digest());
                engine = new DSADigestSigner(new ECDSASigner(), digest);
                break;
            case ALG_ECDSA_SHA_512:
                digest = new NullableDigest(new SHA512Digest());
                engine = new DSADigestSigner(new ECDSASigner(), digest);
                break;
        }
    }

    public void init(Key theKey, byte theMode) throws CryptoException {
        if (theKey == null) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (!theKey.isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (!(theKey instanceof KeyWithParameters)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        engine.init(theMode == MODE_SIGN, ((KeyWithParameters) theKey).getParameters());
        this.key = theKey;
        isInitialized = true;
    }

    public void init(Key theKey, byte theMode, byte[] bArray, short bOff, short bLen) throws CryptoException {
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    public short getLength() throws CryptoException {
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        if (!key.isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        switch (algorithm) {
            case ALG_RSA_SHA_ISO9796:
            case ALG_RSA_SHA_PKCS1:
            case ALG_RSA_SHA_224_PKCS1:
            case ALG_RSA_SHA_256_PKCS1:
            case ALG_RSA_SHA_384_PKCS1:
            case ALG_RSA_SHA_512_PKCS1:
            case ALG_RSA_MD5_PKCS1:
            case ALG_RSA_RIPEMD160_ISO9796:
            case ALG_RSA_RIPEMD160_PKCS1:
                return (short)(key.getSize()>>3);
            case ALG_ECDSA_SHA:
            case ALG_ECDSA_SHA_256:
            case ALG_ECDSA_SHA_224:
            case ALG_ECDSA_SHA_384:
            case ALG_ECDSA_SHA_512:
                // x,y + der payload
                return (short)(((key.getSize()*2)>>3) + 8);
        }
        return 0;
    }

    public byte getAlgorithm() {
        return algorithm;
    }

    public void update(byte[] inBuff, short inOffset, short inLength) throws CryptoException {
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        engine.update(inBuff, inOffset, inLength);
    }

    public short sign(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset) throws CryptoException {
        if (isRecovery) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        engine.update(inBuff, inOffset, inLength);
        byte[] sig;
        try {
            sig = engine.generateSignature();
            Util.arrayCopyNonAtomic(sig, (short) 0, sigBuff, sigOffset, (short) sig.length);
            return (short) sig.length;
        } catch (org.bouncycastle.crypto.CryptoException ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        } catch (DataLengthException ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        } finally {
            engine.reset();
        }
        return -1;
    }

    public boolean verify(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset, short sigLength) throws CryptoException {
        if (isRecovery) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        engine.update(inBuff, inOffset, inLength);
        byte[] sig = new byte[sigLength];
        Util.arrayCopyNonAtomic(sigBuff, sigOffset, sig, (short) 0, sigLength);
        boolean b = engine.verifySignature(sig);
        engine.reset();
        return b;
    }

    public short beginVerify(byte[] sigAndRecDataBuff, short buffOffset, short sigLength) throws CryptoException {
        if (!isRecovery) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        preSig = JCSystem.makeTransientByteArray(sigLength, JCSystem.CLEAR_ON_RESET);
        Util.arrayCopyNonAtomic(sigAndRecDataBuff, buffOffset, preSig, (short) 0, sigLength);
        try {
            ((SignerWithRecovery) engine).updateWithRecoveredMessage(preSig);
            return (short) ((SignerWithRecovery) engine).getRecoveredMessage().length;
        } catch (Exception ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        return -1;
    }

    public short sign(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset, short[] recMsgLen,
            short recMsgLenOffset) throws CryptoException {
        if (!isRecovery) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        engine.update(inBuff, inOffset, inLength);
        byte[] sig;
        try {
            sig = engine.generateSignature();
            Util.arrayCopyNonAtomic(sig, (short) 0, sigBuff, sigOffset, (short) sig.length);
            // there is no direct way to obtain encoded message length
            int keyBits = key.getSize();
            Field messageLengthField = engine.getClass().getDeclaredField("messageLength");
            messageLengthField.setAccessible(true);
            int messageLength = messageLengthField.getInt(engine);
            int digSize = 20;
            int x = (digSize + messageLength) * 8 + 16 + 4 - keyBits;
            int mR = messageLength;
            if (x > 0) {
                mR = messageLength - ((x + 7) / 8);
            }
            recMsgLen[recMsgLenOffset] = (short) mR;
            return (short) sig.length;
        } catch (org.bouncycastle.crypto.CryptoException ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        } catch (DataLengthException ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        } catch (Exception ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        } finally {
            engine.reset();
        }
        return -1;
    }

    public boolean verify(byte[] inBuff, short inOffset, short inLength) throws CryptoException {
        if(!isRecovery){
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        if(preSig == null){
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        engine.update(inBuff, inOffset, inLength);
        boolean b = engine.verifySignature(preSig);
        engine.reset();
        return b;
    }

    public void setInitialDigest(byte[] bytes, short s, short s1, byte[] bytes1, short s2, short s3) throws CryptoException {
        throw new UnsupportedOperationException("Not supported yet."); 
    }

    public short signPreComputedHash(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset) throws CryptoException {
        digest.setNulled(true);
        short res = sign(inBuff, inOffset, inLength, sigBuff, sigOffset);
        digest.setNulled(false);
        return res;
    }
    public boolean verifyPreComputedHash(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset, short sigLength) throws CryptoException {
        digest.setNulled(true);
        boolean res = verify(inBuff, inOffset, inLength, sigBuff, sigOffset, sigLength);
        digest.setNulled(false);
        return res;
    }

    public byte getPaddingAlgorithm() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    public byte getCipherAlgorithm() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    public byte getMessageDigestAlgorithm() {
       throw new UnsupportedOperationException("Not supported yet.");
    }   
}
