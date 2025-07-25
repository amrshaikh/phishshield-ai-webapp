// netlify/functions/analyze-email.js

// This function acts as a proxy to the Gemini API, keeping your API key secure.
// It should be deployed as a Netlify Function (or similar serverless function).

const { GoogleGenerativeAI } = require("@google/generative-ai");

exports.handler = async (event, context) => {
    // Ensure this function only responds to POST requests
    if (event.httpMethod !== "POST") {
        return {
            statusCode: 405,
            body: "Method Not Allowed",
        };
    }

    // Retrieve the API key from Netlify Environment Variables
    // Make sure to set a Netlify Environment Variable named GEMINI_API_KEY
    const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

    if (!GEMINI_API_KEY) {
        console.error("GEMINI_API_KEY environment variable is not set.");
        return {
            statusCode: 500,
            body: JSON.stringify({ error: "Server configuration error: API key missing." }),
        };
    }

    try {
        const { emailContent } = JSON.parse(event.body);

        if (!emailContent) {
            return {
                statusCode: 400,
                body: JSON.stringify({ error: "Missing 'emailContent' in request body." }),
            };
        }

        // Initialize the Google Generative AI client with the secure API key
        const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
        const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash" });

        const prompt = `
            You are PhishShield AI, an expert cybersecurity system specializing in comprehensive email threat analysis.
            Analyze the following full email source (headers and body).

            1.  **Header Analysis**:
                -   First, identify the email headers. If no headers are found, state that in the assessment.
                -   Extract "From", "To", "Reply-To", and "Return-Path".
                -   Simulate SPF and DKIM checks, providing a status ("Pass", "Fail", "Not Found") and a brief reason.
                -   Check for domain mismatches between "From", "Reply-To", and "Return-Path".
                -   Provide an overall header assessment ("Authentic", "Suspicious", "Anomalous") and a summary.

            2.  **Content Analysis**:
                -   Analyze the email body for phishing indicators (e.g., urgency, threats, grammar, generic greetings).
                -   Extract all hyperlinks, noting any mismatch between display text and the actual URL, and assess their risk ("Low", "Medium", "High").
                -   Identify mentioned attachments and flag suspicious file types (.zip, .exe, .docm, etc.), assessing their risk.

            3.  **Overall Verdict**:
                -   Based on both header and content analysis, provide a final classification: "Safe", "Suspicious", or "Phishing".
                -   Provide a confidence score (0.0 to 1.0).
                -   List the key findings that led to your verdict.
                -   Provide 2-3 actionable security tips for the user based on the findings.

            Return the analysis ONLY in the following valid JSON format. If a section has no findings, return an empty array [] or a null/default value. Use "N/A" for missing header fields.
            {
              "classification": "...",
              "confidence": 0.0,
              "explanation": [
                {"feature": "Urgency", "details": "The email creates a false sense of urgency..."}
              ],
              "headerAnalysis": {
                "from": "...", "to": "...", "replyTo": "...", "returnPath": "...",
                "spf": {"status": "Pass", "reason": "Sender is authorized."},
                "dkim": {"status": "Pass", "reason": "Signature is valid."},
                "domainMismatch": {"status": false, "reason": "All sender domains match."},
                "assessment": {"status": "Authentic", "summary": "Headers appear authentic."}
              },
              "analyzedLinks": [
                {"text": "Click Here", "href": "http://malicious.com/...", "risk": "High", "reason": "URL mismatch and suspicious domain."}
              ],
              "analyzedAttachments": [
                {"filename": "invoice.zip", "risk": "High", "reason": ".zip files can contain malware."}
              ],
              "securityTips": [
                "Always verify sender addresses.", "Hover over links before clicking."
              ]
            }

            Here is the email source to analyze:
            ---
            ${emailContent}
            ---
        `;

        const result = await model.generateContent(prompt);
        const response = await result.response;
        const text = response.text();

        // Attempt to parse the JSON output from the model
        const match = text.match(/```json\s*([\s\S]*?)\s*```|(\{[\s\S]*\})/);
        let parsedResult;
        if (match) {
            try {
                parsedResult = JSON.parse(match[1] || match[2]);
            } catch (e) {
                console.error("Failed to parse AI response JSON:", e);
                return {
                    statusCode: 500,
                    body: JSON.stringify({ error: "AI returned malformed JSON.", rawResponse: text }),
                };
            }
        } else {
            console.error("AI response did not contain valid JSON format:", text);
            return {
                statusCode: 500,
                body: JSON.stringify({ error: "AI response did not contain valid JSON format.", rawResponse: text }),
            };
        }

        return {
            statusCode: 200,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(parsedResult),
        };

    } catch (error) {
        console.error("Error in Netlify function:", error);
        return {
            statusCode: 500,
            body: JSON.stringify({ error: "Failed to analyze email.", details: error.message }),
        };
    }
};
