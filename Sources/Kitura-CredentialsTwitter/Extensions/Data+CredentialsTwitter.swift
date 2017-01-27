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

enum TwitterResponseError: Error {
    case dataNotString
    case noQueryComponents(String)
    case noKeyValuePairs(String)
}

extension Data {
    func twitterResponseDictionary() throws -> [String: String] {
        var responseDictionary = [String : String]()
        
        guard let string = String(data: self, encoding: String.Encoding.utf8) else {
            throw TwitterResponseError.dataNotString
        }
        let fields = string.components(separatedBy: "&")
        
        if fields.count == 0 {
            throw TwitterResponseError.noQueryComponents(string)
        }
        for field in fields {
            let keyValue = field.components(separatedBy: "=")
            if let key = keyValue.first,
                let value = keyValue.last {
                responseDictionary[key] = value
            }
            else {
                throw TwitterResponseError.noKeyValuePairs(string)
            }
        }
        return responseDictionary
    }
}
