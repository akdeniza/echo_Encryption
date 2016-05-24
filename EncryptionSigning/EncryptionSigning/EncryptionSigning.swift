import UIKit
import Security

// Constants
private let kEchoApplicationTag = "com.Echo.keypair"
private let kEchoKeyType = kSecAttrKeyTypeRSA
private let kEchoKeySize = 2048
private let kEchoSecPadding: SecPadding = .PKCS1


enum AsymmetricCryptoException: ErrorType {
    case UnknownError
    case DuplicateFoundWhileTryingToCreateKey
    case KeyNotFound
    case AuthFailed
    case UnableToAddPublicKeyToKeyChain
    case WrongInputDataFormat
    case UnableToEncrypt
    case UnableToDecrypt
    case UnableToSignData
    case UnableToVerifySignedData
    case UnableToPerformHashOfData
    case UnableToGenerateAccessControlWithGivenSecurity
    case OutOfMemory
}

class EncryptionSigning: NSObject {
    
    var blockSize : Int?
    var publicKey : SecKey?
    
    override init() {
        super.init()
        self.publicKey = self.getPublicKey()
        
        if self.publicKey == nil {
            self.createSecureKeyPair()
        }
        
        self.blockSize = SecKeyGetBlockSize(self.publicKey!)
    }
    
    
    // MARK: - Manage keys
    
    func createSecureKeyPair() -> (success: Bool, error: AsymmetricCryptoException?) {
        let publicKeyParameters: [String : AnyObject] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: kEchoApplicationTag,
            kSecAttrAccessible as String: kSecAttrAccessibleAlways
        ]
        
        let privateKeyParameters: [String: AnyObject] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: kEchoApplicationTag,
            kSecAttrAccessible as String: kSecAttrAccessibleAlways
        ]
        
        let parameters: [String: AnyObject] = [
            kSecAttrKeyType as String:          kEchoKeyType,
            kSecAttrKeySizeInBits as String:    kEchoKeySize,
            kSecPublicKeyAttrs as String:       publicKeyParameters,
            kSecPrivateKeyAttrs as String:      privateKeyParameters,
            ]
        
        var privateKey: SecKey?
        let status = SecKeyGeneratePair(parameters, &self.publicKey, &privateKey)
        
        if status == errSecSuccess {
            return (true, nil)
        } else {
            var error = AsymmetricCryptoException.UnknownError
            switch (status) {
            case errSecDuplicateItem: error = .DuplicateFoundWhileTryingToCreateKey
            case errSecItemNotFound: error = .KeyNotFound
            case errSecAuthFailed: error = .AuthFailed
            default: break
            }
            return(false, error)
        }
    }
    
    private func getPublicKey() -> SecKey? {
        let parameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrApplicationTag as String: kEchoApplicationTag,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecReturnRef as String: true,
            ]
        
        var ref: AnyObject?
        let status = SecItemCopyMatching(parameters, &ref)
        
        if status == errSecSuccess {
            return ref as! SecKey?
        } else {
            return nil
        }
    }
    
    private func getPrivateKey() -> SecKey? {
        let parameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: kEchoApplicationTag,
            kSecReturnRef as String: true,
            ]
        
        var ref: AnyObject?
        let status = SecItemCopyMatching(parameters, &ref)
        
        if status == errSecSuccess {
            return ref as! SecKey?
        } else {
            return nil
        }
    }
    
    func deleteSecureKeyPair() -> Void {
        // private query dictionary
        let deleteQuery = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: kEchoApplicationTag,
            ]
        
        SecItemDelete(deleteQuery) // delete private key  }
    }
    
    // MARK: - Cypher and decypher methods
    
    func encryptMessageWithPublicKey(message: String) -> (encryptedData: [UInt8]?, encryptedDataLength: Int?)
    {
        
        let plainTextData = [UInt8](message.utf8)
        let plainTextDataLength = message.characters.count
        
        var encryptedData = [UInt8](count: Int(self.blockSize!), repeatedValue: 0)
        var encryptedDataLength = self.blockSize
        
        SecKeyEncrypt(publicKey!, kEchoSecPadding, plainTextData, plainTextDataLength,  &encryptedData, &encryptedDataLength!)
        
        return (encryptedData, encryptedDataLength)
        
    }
    
    func decryptMessageWithPrivateKey(encryptedData: [UInt8], encryptedDataLength: Int) -> (success: Bool, error: AsymmetricCryptoException?, message: String?) {
        
        if let privateKey = self.getPrivateKey() {
            // prepare input input plain text
            var decryptedData = [UInt8](count: Int(self.blockSize!), repeatedValue: 0)
            var decryptedDataLength = self.blockSize
            
            let status = SecKeyDecrypt(privateKey, kEchoSecPadding, encryptedData, encryptedDataLength, &decryptedData, &decryptedDataLength!)
            
            if status == errSecSuccess {
                // Generate and return result string
                let string = String(bytes: decryptedData, encoding:NSUTF8StringEncoding)
                return (true, nil, string)
            } else {
                return(false, .UnableToDecrypt, nil)
            }
        } else {
            return(false, AsymmetricCryptoException.KeyNotFound, nil)
        }
    }
    
    
    
    
    func signMessageWithPrivateKey(message:String) -> (success: Bool, data:NSData?){
        
        if let privateKeyRef = self.getPrivateKey() {
            
            guard let resultData = NSMutableData(length: SecKeyGetBlockSize(privateKeyRef)) else {                return (success:false, data:nil)
            }
            let resultPointer    = UnsafeMutablePointer<UInt8>(resultData.mutableBytes)
            var resultLength     = resultData.length
            
            if let plainData = message.dataUsingEncoding(NSUTF8StringEncoding) {
                // generate hash of the plain data to sign
                guard let hashData = NSMutableData(length: Int(CC_SHA1_DIGEST_LENGTH)) else {                    return (success:false, data:nil)
                }
                let hash = UnsafeMutablePointer<UInt8>(hashData.mutableBytes)
                CC_SHA1(UnsafePointer<Void>(plainData.bytes), CC_LONG(plainData.length), hash)
                
                // sign the hash
                let status = SecKeyRawSign(privateKeyRef, SecPadding.PKCS1SHA1, hash, hashData.length, resultPointer, &resultLength)
                if status != errSecSuccess {
                    return (success:false, data:nil)
                }  else { resultData.length = resultLength }
                hash.destroy()
            } else { return (success:false, data:nil) }
            
            resultData.length = resultLength
            return (success: true, data: resultData)
            
        }else{
            return (success:false, data:nil)
        }
        return (success:false, data:nil)
    }
    
    func verifySignaturePublicKey(data: NSData, signatureData: NSData) -> Bool {
            if let publicKeyRef = self.getPublicKey() {

                guard let hashData = NSMutableData(length: Int(CC_SHA1_DIGEST_LENGTH)) else {
                   return false
                }
                let hash = UnsafeMutablePointer<UInt8>(hashData.mutableBytes)
                CC_SHA1(UnsafePointer<Void>(data.bytes), CC_LONG(data.length), hash)

                let signaturePointer = UnsafePointer<UInt8>(signatureData.bytes)
                let signatureLength = signatureData.length
                
                let status = SecKeyRawVerify(publicKeyRef, SecPadding.PKCS1SHA1, hash, Int(CC_SHA1_DIGEST_LENGTH), signaturePointer, signatureLength)
                
                hash.destroy()

                return status == errSecSuccess
            } else {
                return false
            }
    }

    





}
