window.addEventListener("load", () => {
    let generatedPKCS12B64 = null;

    const displayError = (msg) => {
        console.error("Error on frontend JS", msg);
        document.getElementById("jsErrorAlert").style.display = 'block';
        document.getElementById("jsErrorAlertStack").innerText = msg;
    }

    const generatePKCS12Password = () => {
        const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        const result = [];

        while (result.length < 12) {
            const [byte] = crypto.getRandomValues(new Uint8Array(1));
            // 252 = floor(256/36)*36, discard values that cause bias
            if (byte < 252) {
                result.push(chars[byte % 36]);
            }
        }

        return result.join('');
    }

    const parseKeyAlgorithm = (keyAlg) => {
        const parts = keyAlg.split("/");

        switch (parts[0]) {
            case "RSASSA-PKCS1-v1_5":
            case "RSA-PSS":
                const hashDigestSize = {
                    "SHA-256": 32,
                    "SHA-384": 48,
                    "SHA-512": 64,
                }

                if (!hashDigestSize.hasOwnProperty(parts[2])) {
                    throw Error("Unsupported hash: " + parts[2])
                }

                const saltLength = hashDigestSize[parts[2]];

                return {
                    name: parts[0],
                    modulusLength: parseInt(parts[1]),
                    hash: parts[2],
                    publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
                    saltLength: saltLength,
                }

            case "ECDSA":
                return {
                    name: "ECDSA",
                    namedCurve: parts[1],
                    hash: parts[2]
                };

            case "Ed25519":
                return {
                    name: "Ed25519",
                }
        }
    }

    const clientSideCSRGen = async () => {
        const alg = parseKeyAlgorithm(FRONTEND_CFG.clientSideFlowConfig.keyAlgorithm);
        const keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
        const privKeyDERB64 = await TinyPKICSR.exportKeyDERB64(keys.privateKey);

        const subjectName =
            FRONTEND_CFG.clientSideFlowConfig.cn
                ? [{"CN": [FRONTEND_CFG.clientSideFlowConfig.cn]}]
                : [];

        const csrPEM = await TinyPKICSR.generateCSR({
            subjectName: subjectName,
            subjectAltNames: FRONTEND_CFG.clientSideFlowConfig.sans,
            keys: keys,
            algorithm: alg,
        });

        const resp = await fetch("/public/api/redeem/client-side", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                "csr": csrPEM,
                "token": FRONTEND_CFG.clientSideFlowConfig.token,
            })
        });

        if (resp.headers.get("Content-Type") !== "application/json" && resp.status != 200) {
            throw new Error("Request failed with status code: " + resp.status);
        }

        const res = await resp.json();

        if (res.error) {
            throw Error("Backend returned error: [" + res.error.code + "] " + res.error.message);
        }

        const pkcs12Password = generatePKCS12Password();

        const pkcs12B64 = await TinyPKICSR.generatePKCS12({
            algorithm: alg,
            certChainPEM: res.certChain,
            privKeyDERB64: privKeyDERB64,
            pkcs12Password: pkcs12Password,
            pkcs12Algorithm: "3des",
        });

        document.getElementById("pkcs12Password").innerText = pkcs12Password;
        generatedPKCS12B64 = pkcs12B64;
    }

    const serverSideCSRGen = async () => {
        const resp = await fetch("/public/api/redeem/server-side", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                "token": FRONTEND_CFG.serverSideFlowConfig.token,
            })
        });

        if (resp.headers.get("Content-Type") !== "application/json" && resp.status != 200) {
            throw new Error("Request failed with status code: " + resp.status);
        }

        const res = await resp.json();

        if (res.error) {
            throw Error("Backend returned error: [" + res.error.code + "] " + res.error.message);
        }

        document.getElementById("pkcs12Password").innerText = FRONTEND_CFG.serverSideFlowConfig.pkcs12_password;
        generatedPKCS12B64 = res.pkcs12B64;
    }

    const performCSRGenFlow = async () => {
        if (FRONTEND_CFG.flowType === "SERVER_SIDE") {
            await serverSideCSRGen();
        } else if (FRONTEND_CFG.flowType === "CLIENT_SIDE") {
            await clientSideCSRGen();
        } else {
            throw Error("Unsupported CSR generation flow: " + FRONTEND_CFG.flowType);
        }

        setUIStep(2);
    }

    const setUIStep = (stepNo) => {
        for (let i = 0; i <= 5; i++) {
            document.getElementById("step" + i).style.display = 'none';
        }

        if (stepNo !== null) {
            document.getElementById("step" + stepNo).style.display = 'block';
        }
    }

    const btnRequestCertificate = async () => {
        document.getElementById("btnRequestCertificate").disabled = true;

        try {
            await performCSRGenFlow();
        } catch (e) {
            console.error("Client-side CSR generation error", e);
            document.getElementById("jsErrorAlert").style.display = 'block';
            document.getElementById("jsErrorAlertStack").innerText = e.stack.toString();
            setUIStep(null);
        }
    }

    const btnPasswordCopied = () => {
        document.getElementById("verifyPasswordInput").value = "";
        setUIStep(3);
    }

    const btnPasswordVerify = () => {
        const enteredPassword = document.getElementById("verifyPasswordInput").value;
        const realPassword = document.getElementById("pkcs12Password").innerText;

        if (enteredPassword !== realPassword) {
            alert("Incorrect password was entered. Please copy the password again.");
            document.getElementById("btnPasswordCopied").disabled = false;
            setUIStep(2);
            return;
        }

        document.getElementById("btnPasswordVerify").disabled = true;
        document.getElementById("btnDownloadPKCS12").disabled = true;

        setUIStep(4);

        setTimeout(function () {
            document.getElementById("btnDownloadPKCS12").disabled = false;
        }, 1500);
    }

    const btnDisplayPasswordAgain = () => {
        setUIStep(2);
    }

    const btnDownloadPKCS12 = () => {
        document.getElementById("btnDownloadPKCS12").disabled = true;
        document.getElementById("btnDownloadPKCS12Again").disabled = true;

        TinyPKICSR.savePKCS12BufferAsFile({
            buffer: TinyPKICSR.base64ToBuffer(generatedPKCS12B64),
            targetName: "bundle.p12"
        });

        setUIStep(4);

        setTimeout(function () {
            document.getElementById("btnDownloadPKCS12Again").disabled = false;
        }, 1500);
    }

    const initFrontend = () => {
        const testCryptoGetRandomValues = () => {
            let isFailed = false;

            const timeout = setTimeout(() => {
                isFailed = true;
                displayError("Failed to test crypto.getRandomValues() - the function call hung for " +
                    "more than 15 seconds.");
            }, 1000 * 15);

            const buf = new Uint8Array(16);
            crypto.getRandomValues(buf);
            clearTimeout(timeout);
            const nonZeroBytes = buf.reduce(
                (acc, val) => (val !== 0 ? acc + 1 : acc), 0);

            if (nonZeroBytes === 0) {
                throw Error("Returned buffer was not populated with random data.");
            }

            if (isFailed) {
                throw Error("Failed to test crypto.getRandomValues() - took more than 15 seconds to generate " +
                    "a random value.")
            }
        }

        if (FRONTEND_CFG.flowType === "SERVER_SIDE") {
            document.getElementById("keyGenFlowType").innerText = "on our server";
        } else if (FRONTEND_CFG.flowType === "CLIENT_SIDE") {
            document.getElementById("keyGenFlowType").innerText = "in your browser";

            // perform some minimal sanity checks whether the Web Crypto API exists and is working
            // note that with some no-name Chromium-based browsers the API might be there, but might just be a no-op
            if (!window.crypto
                || !window.crypto.subtle
                || !window.crypto.subtle.generateKey
                || !window.crypto.getRandomValues
            ) {
                displayError("Unable to detect Web Crypto API.");
                return;
            }

            try {
                testCryptoGetRandomValues();
            } catch (e) {
                displayError("Failed to test crypto.getRandomValues().\n" + e.stack.toString());
                return;
            }
        } else {
            displayError("Unsupported flow type: " + FRONTEND_CFG.flowType);
            return;
        }

        document.getElementById("btnRequestCertificate").addEventListener("click", btnRequestCertificate);
        document.getElementById("btnPasswordCopied").addEventListener("click", btnPasswordCopied);
        document.getElementById("btnPasswordVerify").addEventListener("click", btnPasswordVerify);
        document.getElementById("btnDisplayPasswordAgain").addEventListener("click", btnDisplayPasswordAgain);
        document.getElementById("verifyPasswordInput").addEventListener("keydown", (event) => {
            if (event.key === 'Enter') {
                btnPasswordVerify();
            }
        });
        document.getElementById("btnDownloadPKCS12").addEventListener("click", btnDownloadPKCS12);
        document.getElementById("btnDownloadPKCS12Again").addEventListener("click", btnDownloadPKCS12);

        setUIStep(1);
    };

    initFrontend();
});
