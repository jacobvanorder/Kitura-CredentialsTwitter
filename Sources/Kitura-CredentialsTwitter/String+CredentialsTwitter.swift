//
//  String+CredentialsTwitter.swift
//  Kitura-CredentialsTwitter
//
//  Created by mrJacob on 1/16/17.
//
//

import Foundation

import Cryptor

public extension String {
    static var nonce: String {
        return UUID().uuidString.components(separatedBy: "-").first!
    }
    
    static func oAuthAuthorizationString(fromParameters parameters: [String: String]) -> String {
        var keyValues = [String]()
        for (key, value) in parameters {
            keyValues.append("\(key)=\"\(value)\"")
        }
        return "OAuth " + keyValues.sorted().joined(separator: ",")
    }
    
    //https://dev.twitter.com/oauth/overview/creating-signatures
    static func oAuthSignature(fromMethod method: String, url: String, parameters: [String:String], with consumerSecret: String, oAuthToken: String = "") -> String? {
        var keyValues = [String]()
        for (key, value) in parameters {
            keyValues.append("\(key)=\(value.addingPercentEncoding(withAllowedCharacters: .twitterParameterStringSet)!)")
        }
        let sortedParameters = keyValues.sorted(by: {$0 < $1})
        let joinedParameters = sortedParameters.joined(separator: "&")
        guard let percentEncodedUrl = url.addingPercentEncoding(withAllowedCharacters: .twitterParameterStringSet),
            let percentEncodedJoinedParameters = joinedParameters.addingPercentEncoding(withAllowedCharacters: .twitterParameterStringSet),
            let percentEncodedConsumerSecret = consumerSecret.addingPercentEncoding(withAllowedCharacters: .twitterParameterStringSet) else {
                return nil
        }
        
        let rawString = [method, percentEncodedUrl, percentEncodedJoinedParameters].joined(separator: "&")
        
        let hmac = HMAC(using: .sha1, key: percentEncodedConsumerSecret + "&" + oAuthToken)
        let encryptedKey = hmac.update(string: rawString)!
        let encodedRawBytes = encryptedKey.final()
        let encodedData = Data(bytes: encodedRawBytes)
        let encodedString = encodedData.base64EncodedString()
        return encodedString.addingPercentEncoding(withAllowedCharacters: .twitterParameterStringSet)!
    }
}
