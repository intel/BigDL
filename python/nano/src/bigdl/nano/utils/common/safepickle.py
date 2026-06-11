#
# Copyright 2016 The BigDL Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import pickle
import hmac
import hashlib
from bigdl.nano.utils.common import invalidInputError

# Refer to this guide https://www.synopsys.com/blogs/software-security/python-pickling/
# To safely use python pickle


class SafePickle:
    _key = None

    @classmethod
    def _get_key(cls):
        if cls._key is None:
            env_key = os.environ.get('BIGDL_SAFE_PICKLE_KEY')
            if env_key:
                cls._key = bytes.fromhex(env_key)
            else:
                cls._key = os.urandom(32)
                os.environ['BIGDL_SAFE_PICKLE_KEY'] = cls._key.hex()
        return cls._key

    @classmethod
    def dump(cls, obj, file, return_digest=False, *args, **kwargs):
        """
        Example:
            >>> from bigdl.nano.utils.common import SafePickle
            >>> with open(file_path, 'wb') as file:
            >>>     SafePickle.dump(data, file)
        """
        pickled_data = pickle.dumps(obj)
        file.write(pickled_data)
        digest = hmac.new(cls._get_key(), pickled_data, hashlib.sha256).hexdigest()
        if return_digest:
            return digest
        sig_path = file.name + '.sig'
        with open(sig_path, 'w') as sig_file:
            sig_file.write(digest)

    @classmethod
    def load(cls, file, digest=None, *args, **kwargs):
        """
        Example:
            >>> from bigdl.nano.utils.common import SafePickle
            >>> with open(file_path, 'rb') as file:
            >>>     data = SafePickle.load(file)
        """
        content = file.read()

        if digest is None:
            sig_path = file.name + '.sig'
            if os.path.exists(sig_path):
                with open(sig_path, 'r') as sig_file:
                    digest = sig_file.read().strip()

        if digest:
            new_digest = hmac.new(cls._get_key(), content, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(digest, new_digest):
                invalidInputError(False,
                                  'Pickle integrity check failed: '
                                  'file may have been tampered with')
        else:
            invalidInputError(False,
                              'No HMAC signature found for pickle file: '
                              'cannot verify integrity')

        return pickle.loads(content, *args, **kwargs)
