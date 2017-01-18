/**
 * Copyright Jacob Van Order 2017
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

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
