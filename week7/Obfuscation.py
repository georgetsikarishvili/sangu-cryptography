#original
def calculate_factorial(number):
    """Calculates the factorial of a number recursively."""
    if number == 1 or number == 0:
        return 1
    else:
        return number * calculate_factorial(number - 1)

print(calculate_factorial(5))

#manual obfuscation
def _(_0):return 1 if _0==1 or _0==0 else _0* _(_0-1)
print(_(5))
'''Manual Obfuscation: Lexical Transformation
What I did: I replaced semantically meaningful names (calculate_factorial, number) with abstract identifiers (_, _0).

Why: This targets the human reader. By removing the descriptive names, the code logic remains identical to the computer, 
but a human creates a mental block trying to decipher what _ represents. It removes the "intent" of the code.'''

#automatic obfuscation
import base64
exec(base64.b64decode('ZGVmIGNhbGN1bGF0ZV9mYWN0b3JpYWwobnVtYmVyKToKICAgIGlmIG51bWJlciA9PSAxIG9yIG51bWJlciA9PSAwOgogICAgICAgIHJldHVybiAxCiAgICBlbHNlOgogICAgICAgIHJldHVybiBudW1iZXIgKiBjYWxjdWxhdGVfZmFjdG9yaWFsKG51bWJlciAtIDEpCgpwcmludChjYWxjdWxhdGVfZmFjdG9yaWFsKDUpKQ=='))
'''Automatic Obfuscation: Encoding/Packing
What I did: The entire source code string was converted into Base64 format. The exec() function is then used 
to decode and run that string at runtime.

Why: This targets static analysis. If a person (or an antivirus scanner) opens the file, they cannot see the 
code structure, keywords, or logic immediately. They only see a block of gibberish text. To understand it, 
they must reverse-engineer the decoding process.'''