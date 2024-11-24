# ##ELIPTIC_SIGNATURE#
# <!DOCTYPE html>
# <html lang="en">

#     <head>
#         <meta charset="UTF-8">
#         <meta name="viewport" content="width=device-width, initial-scale=1.0">
#         <title>ECDSA</title>
#         <link rel="stylesheet" href="{{ url_for('static', filename='css/bootstrap.css') }}">
#     </head>

#     <body>

#         <script src="{{ url_for('static', filename='js/bootstrap.bundle.min.js') }}"></script>

#         <header>
#             <nav class="navbar fixed-top navbar-expand-lg bg-dark navbar-dark">
#                 <div class="container-fluid">
#                   <!-- link to homescreen -->
#                   <a class="navbar-brand" href="#">
#                     <img src="" alt="">
#                     INT3230E
#                   </a>
#                   <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
#                     <span class="navbar-toggler-icon"></span>
#                   </button>
#                   <div class="collapse navbar-collapse" id="navbarSupportedContent">
#                     <ul class="navbar-nav me-auto mb-2 mb-lg-0">
#                         <li class="nav-item dropdown">
#                             <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown" aria-expanded="true">
#                               RSA
#                             </a>
#                             <ul class="dropdown-menu">
#                                 <li><a class="dropdown-item" href="/">RSA</a></li>
#                                 <li><hr class="dropdown-divider"></li>
#                               <li><a class="dropdown-item" href="/rsa-signature">RSA Digital Signature</a></li>
#                             </ul>
#                         </li>
          
#                         <li class="nav-item dropdown">
#                             <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown" aria-expanded="true">
#                               ElGammal
#                             </a>
#                             <ul class="dropdown-menu">
#                                 <li><a class="dropdown-item" href="/elgammal">Elgammal</a></li>
#                                 <li><hr class="dropdown-divider"></li>
#                               <li><a class="dropdown-item" href="/elgammal-signature">Elgammal Digital Signature</a></li>
#                             </ul>
#                         </li>
          
#                         <li class="nav-item dropdown">
#                             <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown" aria-expanded="true">
#                               Elliptic
#                             </a>
#                             <ul class="dropdown-menu">
#                                 <li><a class="dropdown-item" href="/elliptic">ECC</a></li>
#                                 <li><hr class="dropdown-divider"></li>
#                               <li><a class="dropdown-item" href="/elliptic-signature">ECC Digital Signature</a></li>
#                             </ul>
#                         </li>
          
#                         <li class="nav-item dropdown">
#                           <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown" aria-expanded="true">
#                             Fundamentals
#                           </a>
#                           <ul class="dropdown-menu">
#                             <li><a class="dropdown-item" href="/euclid">Euclid algorithm</a></li>
#                             <li><a class="dropdown-item" href="/primality">Primality test</a></li>
#                             <li><hr class="dropdown-divider"></li>
#                             <li><a class="dropdown-item" href="other.html">Something else here</a></li>
#                           </ul>
#                         </li>
#                       </ul>
#                   </div>
#                 </div>
#             </nav>
#         </header>

#         <main class="pt-5">
#             <div class="container">
#                 <h1 class="text-center mt-5">ECDSA (Elliptic Curve Digital Signature Algorithm)</h1>

#                 <div class="d-flex justify-content-center my-5">
#                     <div class="col">
#                       <div class="bg-secondary text-white card">
#                         <div class="card-body">
#                             <!-- <h2 class="text-center">Primality test</h2> -->
#                            <p>The Elliptic Curve Digital Signature Algorithm is a Digital Signature Algorithm (DSA) that uses elliptic curve cryptography keys. It is a very efficient equation that is based on cryptography with public keys. ECDSA is utilized in many security systems, is popular in encrypted messaging apps, and is the foundation of Bitcoin security (with Bitcoin “addresses” serving as public keys).</p>
#                         </div>
#                       </div>
#                     </div>
#                 </div>

#                 <div class="d-flex justify-content-center my-5">
#                     <div class="col">
#                       <div class="bg-secondary text-white card">
#                         <div class="card-body">
#                             <!-- <h2 class="text-center">Primality test</h2> -->
#                            <p>Elliptic Curve Digital Signature Algorithms (ECDSA) have recently received significant attention, particularly from standards developers, as alternatives to existing standard cryptosystems such as integer factorization cryptosystems and discrete logarithm problem cryptosystems. In security applications, crypto-algorithms are always the most significant fundamental tool.</p>
#                         </div>
#                       </div>
#                     </div>
#                 </div>

#                 <h1 class="text-center mt-5">Example</h1>

#                 <div class="card-group mt-5">

#                     <div class="card">
#                         <div class="card-header">
#                             <h4>Bob</h4>
#                         </div>
#                         <div class="card-body">

#                             <!-- connect here: id="Elliptic system setting" -->
#                             <form id="system1_setting">
#                                 <div class="mb-3 row">
#                                     <label for="primeP1" class="col-sm-2 col-form-label"><i>p</i> =</label>
#                                     <div class="col-sm-10">
#                                         <!-- connect here: id="p1" -->
#                                         <input type="number" class="form-control" id="p1" placeholder="11" required />
#                                     </div>
#                                 </div>

#                                 <div class="mb-3 row">
#                                     <label for="a1" class="col-sm-2 col-form-label"><i>a</i> =</label>
#                                     <div class="col-sm-10">
#                                         <!-- connect here: id="a1" -->
#                                         <input type="number" class="form-control" id="a1" placeholder="1" required />
#                                     </div>
#                                 </div>

#                                 <div class="mb-3 row">
#                                     <label for="privateKey1" class="col-sm-2 col-form-label"><i>b</i> =</label>
#                                     <div class="col-sm-10">
#                                         <!-- connect here: id="b1" -->
#                                         <input type="number" class="form-control" id="b1" placeholder="3" required />
#                                     </div>
#                                 </div>

#                                 <div class="mb-3 row">
#                                     <label for="basePoint1" class="col-sm-2 col-form-label"><i>Gx</i> =</label>
#                                     <div class="col-sm-10">
#                                         <!-- connect here: id="Gx1" -->
#                                         <input type="number" class="form-control" id="Gx1" placeholder="3" required />
#                                     </div>
#                                 </div>

#                                 <div class="mb-3 row">
#                                     <label for="basePoint1" class="col-sm-2 col-form-label"><i>Gy</i> =</label>
#                                     <div class="col-sm-10">
#                                         <!-- connect here: id="Gy1" -->
#                                         <input type="number" class="form-control" id="Gy1" placeholder="3" required />
#                                     </div>
#                                 </div>

#                                 <div class="mb-3 row">
#                                     <label for="privateKey1" class="col-sm-2 col-form-label">Private key</label>
#                                     <div class="col-sm-10">
#                                         <!-- connect here: id="privateKey1" -->
#                                         <input type="number" class="form-control" id="privateKey1" placeholder="3" required />
#                                     </div>
#                                 </div>

#                                 <div class="mb-3 row">
#                                     <label for="message1" class="col-sm-2 col-form-label">Message:</label>
#                                     <div class="col-sm-10">
#                                         <!-- connect here: id="message1" -->
#                                         <input type="text" class="form-control" id="message1" placeholder="Hello Alice" required />
#                                     </div>
#                                 </div>

#                                 <div class="d-flex justify-content-begin">
#                                     <!-- connect here: handle form submission -->
#                                     <button type="submit" class="btn btn-primary">Submit</button>
#                                 </div>
#                             </form>                            
#                         </div>
#                     </div>

#                     <div class="card">
#                         <div class="card-header">
#                             <h4>Alice</h4>
#                         </div>
#                         <div class="card-body">

#                             <!-- connect here: id="Elliptic system setting" -->
#                             <form id="system2_setting">
#                                 <div class="mb-3 row">
#                                     <label for="primeP2" class="col-sm-2 col-form-label"><i>p</i> =</label>
#                                     <div class="col-sm-10">
#                                         <!-- connect here: id="p2" -->
#                                         <input type="number" class="form-control" id="p2" placeholder="11" required />
#                                     </div>
#                                 </div>

#                                 <div class="mb-3 row">
#                                     <label for="a2" class="col-sm-2 col-form-label"><i>a</i> =</label>
#                                     <div class="col-sm-10">
#                                         <!-- connect here: id="a2" -->
#                                         <input type="number" class="form-control" id="a2" placeholder="1" required />
#                                     </div>
#                                 </div>

#                                 <div class="mb-3 row">
#                                     <label for="b2" class="col-sm-2 col-form-label"><i>b</i> =</label>
#                                     <div class="col-sm-10">
#                                         <!-- connect here: id="b2" -->
#                                         <input type="number" class="form-control" id="b2" placeholder="3" required />
#                                     </div>
#                                 </div>

#                                 <div class="mb-3 row">
#                                     <label for="basePoint2" class="col-sm-2 col-form-label"><i>Gx</i> =</label>
#                                     <div class="col-sm-10">
#                                         <!-- connect here: id="Gx2" -->
#                                         <input type="number" class="form-control" id="Gx2" placeholder="3" required />
#                                     </div>
#                                 </div>

#                                 <div class="mb-3 row">
#                                     <label for="basePoint2" class="col-sm-2 col-form-label"><i>Gy</i> =</label>
#                                     <div class="col-sm-10">
#                                         <!-- connect here: id="Gy2" -->
#                                         <input type="number" class="form-control" id="Gy2" placeholder="3" required />
#                                     </div>
#                                 </div>

#                                 <div class="mb-3 row">
#                                     <label for="privateKey2" class="col-sm-2 col-form-label">Private key</label>
#                                     <div class="col-sm-10">
#                                         <!-- connect here: id="privateKey2" -->
#                                         <input type="number" class="form-control" id="privateKey2" placeholder="3" required />
#                                     </div>
#                                 </div>

#                                 <div class="mb-3 row">
#                                     <label for="message2" class="col-sm-2 col-form-label">Message:</label>
#                                     <div class="col-sm-10">
#                                         <!-- connect here: id="message2" -->
#                                         <input type="text" class="form-control" id="message2" placeholder="Hello Bob" required />
#                                     </div>
#                                 </div>

#                                 <div class="d-flex justify-content-begin">
#                                     <!-- connect here: handle form submission -->
#                                     <button type="submit" class="btn btn-primary">Submit</button>
#                                 </div>
#                             </form>                            
#                         </div>
#                     </div>
#                 </div>

#                 <!-- From Bob to Alice  -->
#                 <div class="card my-5">
#                     <div class="card-header">
#                         <h4>From: Bob, to: Alice</h4>
#                     </div>
#                     <div class="card-body">
#                         <h6 class="fw-bold">&rArr; Sending & Receving Process:</h6>
#                         <div class="card-group mt-3">

#                             <div class="card">
#                                 <div class="card-header">
#                                     <h5 class="text-center">Sender</h5>
#                                 </div>
#                                 <div class="card-body">
#                                     <p class="card-text">Bob sends the message to Alice.</p>
#                                     <!-- conect here: id="signature1" -->
#                                     <p class="card-text">Sender: </p>
#                                     <!-- connect here: id="message1" -->
#                                     <p class="card-text">Message: <span id="message12">Hello Alice</span></p>
#                                     <!-- connect here: id="hashed_message1" -->
#                                     <p class="card-text">Hashed message: <span id="hashed_message1">?</span></p>
#                                     <!-- connect here: id="encrypted_signature1" -->
#                                     <p class="card-text">Signature: <span id="signature1">?</span></p>
#                                     <!-- connect here: id="encrypted_message1" -->
#                                     <p class="card-text">Encrypted message: <span id="encrypted_message1">?</span></p>
#                                     <p class="card-text">Bob public key: <span id="Bob_public_key">(n, e)</span></p>

#                                     <p class="card-text">Bob private key: <span id="Bob_private_key">(n, d)</span></p>
#                                 </div>
#                             </div>

#                             <div class="card">
#                                 <div class="card-header">
#                                     <h5 class="text-center">Receiver</h5>
#                                 </div>
#                                 <div class="card-body">
#                                     <p class="card-text">Alice receives the message from Bob.</p>
#                                     <!-- connect here: id="signature2" -->
#                                     <p class="card-text">Receiver: <span id="signature2">Alice</span></p>
#                                     <!-- connect here: id="signature_authentication1" -->
#                                     <p class="card-text">Decrypt message: <span id="decrypted_message1">?</span></p>
#                                     <p class="card-text">Signature authentication: <span id="signature_authentication1">Invalid</span></p>
#                                     <p class="card-text"><ul>
#                                         <li>
#                                             <i>u₁ = <span id="h1">h</span> · <span id="w1">w</span> mod <span id="n1">n</span></i>
#                                         </li>
#                                         <li>
#                                             <i>u₂ = <span id="r1">r</span> · <span id="w12">w</span> mod <span id="n12">n</span></i>
#                                         </li>
                                        
#                                         <li>
#                                             <i>P = <span id="u1">u₁</span> · <span id="G1">G</span> + <span id="u21">u₂</span> · <span id="Q1">Q</span></i>
#                                         </li>
#                                         <li>
#                                             Verify: <i><span id="r_check1">r</span> ≡ <span id="x21">x₂</span> mod <span id="n13">n</span></i>.
#                                         </li>
#                                      </p>
#                                     <!-- connect here: id="decrypted_message1" -->
#                                 </div>
#                             </div>

#                         </div>
#                     </div>
#                 </div>
                
#                 <!-- From Alice to Bob  -->
#                 <div class="card my-5">
#                     <div class="card-header">
#                         <h4>From: Alice, to: Bob</h4>
#                     </div>
#                     <div class="card-body">
#                         <h6 class="fw-bold">&rArr; Sending & Receving Process:</h6>
#                         <div class="card-group">
                                
#                             <div class="card">
#                                 <div class="card-header">
#                                     <h5 class="text-center">Sender</h5>
#                                 </div>
#                                 <div class="card-body">
#                                     <p class="card-text">Alice sends the message to Bob.</p>
#                                     <!-- conect here: id="signature2" -->
#                                     <p class="card-text">Sender: <span id="signature2">Alice</span></p>
#                                     <!-- connect here: id="message2" -->
#                                     <p class="card-text">Message: <span id="message22">Hello Bob</span></p>
#                                     <!-- connect here: id="hashed_signature2" -->
#                                     <!-- connect here: id="hashed_message2" -->
#                                     <p class="card-text">Hashed message: <span id="hashed_message2">?</span></p>

#                                     <p class="card-text">Signature: <span id="signature2">?</span></p>
                                    
#                                     <!-- connect here: id="encrypted_message2" -->
#                                     <p class="card-text">Encrypted message: <span id="encrypted_message2">?</span></p>
#                                     <p class="card-text">Alice public key: <span id="Alice_public_key">(n, e)</span></p>

#                                     <p class="card-text">Alice private key: <span id="Alice_private_key">(n, d)</span></p>
#                                 </div>
#                             </div>

#                             <div class="card">
#                                 <div class="card-header">
#                                     <h5 class="text-center">Receiver</h5>
#                                 </div>
#                                 <div class="card-body">
#                                     <p class="card-text">Bob receives the message from Alice.</p>
#                                     <!-- connect here: id="signature1" -->
#                                     <p class="card-text">Receiver: <span id="signature1">Bob</span></p>
#                                     <!-- connect here: id="signature_authentication2" -->
#                                     <p class="card-text">Decrypt message: <span id="decrypted_message2">?</span></p>
#                                     <p class="card-text">Signature authentication: <span id="signature_authentication2">Invalid</span></p>
#                                     <p class="card-text"><ul>
#                                         <li>
#                                             <i>u₁ = <span id="h2">h(M)</span> · <span id="w2">w</span> mod <span id="n2">n</span></i>
#                                         </li>
#                                         <li>
#                                             <i>u₂ = <span id="r2">r</span> · <span id="w2">w</span> mod <span id="n2">n</span></i>
#                                         </li>
                                        
#                                         <li>
#                                             <i>P = <span id="u12">u₁</span> · <span id="G2">G</span> + <span id="u22">u₂</span> · <span id="Q2">Q</span></i>
#                                         </li>
#                                         <li>
#                                             Verify: <i><span id="r_check2">r</span> ≡ <span id="x22">x₂</span> mod <span id="n2">n</span></i>.
#                                         </li>
#                                      </p>
#                                 </div>
#                             </div>
#                         </div>
#                     </div>
#                 </div>
#             </div>
#         </main>

#         <footer class="text-center mt-auto py-3 text-white bg-dark fixed-bottom">
#             <div class="text-center p-0.5">
#               INT3230E - Cryptography & Information Security: Nguyễn Hữu Thế & Hoàng Kim Chi
#             </div>
#         </footer>
#         <script>
#             document.querySelector("#system1_setting").addEventListener("submit", async function (e) {
#                 e.preventDefault(); // Ngăn chặn reload trang
            
#                 // Lấy giá trị từ form
#                 const p = parseInt(document.querySelector("#p1").value);
#                 const a = parseInt(document.querySelector("#a1").value);
#                 const b = parseInt(document.querySelector("#b1").value);
#                 const Gx = parseInt(document.querySelector("#Gx1").value);
#                 const Gy = parseInt(document.querySelector("#Gy1").value);
#                 const d = parseInt(document.querySelector("#privateKey1").value);
#                 const message = document.querySelector("#message1").value;
            
#                 // Tạo request payload
#                 const payload = {
#                     p, a, b, Gx, Gy, d, message
#                 };
            
#                 try {
#                     // Gửi POST request đến API
#                     const response = await fetch('/sign_elip', {
#                         method: 'POST',
#                         headers: {
#                             'Content-Type': 'application/json',
#                         },
#                         body: JSON.stringify(payload),
#                     });
            
#                     // Nhận phản hồi JSON từ server
#                     const result = await response.json();
            
#                     // Hiển thị dữ liệu trên giao diện
#                     document.querySelector("#hashed_message1").textContent = result.hashed_message;
#                     document.querySelector("#signature1").textContent = JSON.stringify(result.signature);
#                     document.querySelector("#encrypted_message1").textContent = `(${JSON.stringify(result.C1)}, ${JSON.stringify(result.C2)})`;
#                     document.querySelector("#Bob_public_key").textContent = `s = ${JSON.stringify(result.public_key)}`;
#                     document.querySelector("#Bob_private_key").textContent = `B = ${JSON.stringify(result.private_key)}`;
#                     document.querySelector("#decrypted_message1").textContent = JSON.stringify(result.decrypted_message);
#                     document.querySelector("#signature_authentication1").textContent = result.v ? "Valid" : "Invalid";

#                     document.getElementById('h1').textContent = result.hashed_message;
#                     document.getElementById('w1').textContent = result.w;
#                     document.getElementById('n1').textContent = result.n;

#                     document.getElementById('r1').textContent = values.signature[0];
#                     document.getElementById('w12').textContent = result.w;
#                     document.getElementById('n12').textContent = result.n;

#                     document.getElementById('u1').textContent = result.u1;
#                     document.getElementById('G1').textContent = `(${Gx}, ${Gy})`;
#                     document.getElementById('u21').textContent = values.u2;
#                     document.getElementById('Q1').textContent = `(${result.public_key[0]}, ${result.public_key[1]})`;

#                     document.getElementById('r_check1').textContent = values.signature[0];
#                     document.getElementById('x21').textContent = result.P[0];
#                     document.getElementById('n13').textContent = result.n;
            
#                 } catch (error) {
#                     console.error("Error:", error);
#                     alert("An error occurred while processing the request.");
#                 }
#             });
#         </script>
#     </body>

# </html>