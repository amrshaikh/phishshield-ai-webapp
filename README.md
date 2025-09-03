# 🛡️ PhishShield AI

An AI-powered web application designed to help you identify and protect against tricky phishing emails. This tool uses the power of AI to analyze all the email details—from the headers to the attachments—giving you a clear verdict and helping you stay safe.

-----

## ✨ Key Features

  * **Instant Analysis**: Get an instant verdict by pasting raw email content or uploading `.eml`, `.txt`, or `.pdf` files.
  * **🧠 AI-Powered Verdict**: Our system leverages the Google Gemini API to classify emails as "**Safe**" ✅, "**Suspicious**" 🤔, or "**Phishing**" 🚨, all with a confidence score.
  * **🔐 Secure by Design**: Your API key is safely tucked away in a [Netlify serverless function](https://www.netlify.com/products/functions/), so it's never exposed in your public code.
  * **💡 Explainable Predictions**: We don't just give you a verdict—we show you exactly why. Get a detailed breakdown of findings, including header analysis, suspicious links, and attachment risks.
  * **📚 User Education**: We provide actionable security tips with every scan to help you become your own first line of defense.
  * **📄 Report Generation**: Users can export a full analysis report in either **PDF** or **JSON** format for your records.

-----

## 🚀 How to Use

1.  **Visit the live application:** [https://thefirewallcrew.netlify.app](https://thefirewallcrew.netlify.app)
2.  **Input Email**: Paste the full source of an email into the text area, or upload a supported file.
3.  **Analyze**: Click the "Analyze" button and let the AI do its work\!
4.  **Review Results**: Check the verdict, read the detailed findings, and follow the security tips to protect yourself.

-----

## ⚙️ Technical Stack & Architecture

This project is built on a modern Jamstack (JavaScript, APIs, Markup) architecture for security and speed.

  * **Frontend**: HTML, [Tailwind CSS](https://tailwindcss.com/), and vanilla JavaScript.
  * **Backend**: A [Netlify Serverless Function](https://docs.netlify.com/functions/overview/) (Node.js) acting as a secure proxy.
  * **AI Core**: The [Google Gemini API](https://ai.google.dev/) for all analytical tasks.

-----

## 🧑‍💻 Contributors

This project was built by a dedicated team.

  * **Amr**: [Twitter Profile](https://x.com/amrxshk)
  * **Talha**: [LinkedIn Profile](https://www.linkedin.com/in/talha-chougle-15a063334)
  * **Uzair**: [LinkedIn Profile](https://www.linkedin.com/in/uzair-karedia-61080a348)

-----

## 🤝 Contributing

We welcome contributions\! If you have ideas for new features or bug fixes, feel free to open an issue or submit a pull request.
