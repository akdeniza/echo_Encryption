

import UIKit

class ViewController: UIViewController {
    
    
    

    override func viewDidLoad() {
        super.viewDidLoad()
        
        //Tests zum Signieren und verifizieren in der Konsole
        let manager = EncryptionSigning()
        let text : String = "Hallo Welt"
        let text1 : String = "yo"
        
        // signieren des Textes
        let (success, data) = manager.signMessageWithPrivateKey(text)
        
        print(success)
        print(data)
        
        //Encodieren der Strings
        let rawData = text.dataUsingEncoding(NSUTF8StringEncoding)
        let rawData1 = text1.dataUsingEncoding(NSUTF8StringEncoding)
        
        // verifizieren mittels data und encodiertem Text
        let status = manager.verifySignaturePublicKey(rawData!, signatureData: data!)
        let status2 = manager.verifySignaturePublicKey(rawData1!, signatureData: data!)

        print(status)
        print(status2)
        
        
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }


}

