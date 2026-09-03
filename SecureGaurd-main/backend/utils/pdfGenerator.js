/**
 * SecureGuard PDF Report Generator
 * 
 * Generates professional multi-page PDF compliance assessment reports using PDFKit.
 */

const PDFDocument = require('pdfkit');

/**
 * Builds a PDF document stream/buffer from report data.
 * @param {Object} reportData - Evaluated report data object
 * @returns {Promise<Buffer>} PDF Buffer
 */
function generateCompliancePdf(reportData) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        size: 'A4',
        margin: 40,
        bufferPages: true,
        info: {
          Title: `SecureGuard_${reportData.report.framework}_Report_${reportData.report.repositoryName}`,
          Author: 'SecureGuard Security Platform',
          Subject: 'Security Compliance Assessment'
        }
      });

      const buffers = [];
      doc.on('data', chunk => buffers.push(chunk));
      doc.on('end', () => resolve(Buffer.concat(buffers)));
      doc.on('error', err => reject(err));

      const primaryColor = '#0055FF';
      const darkBg = '#0B0F19';
      const cardBg = '#111827';
      const textMain = '#111827';
      const textDim = '#4B5563';
      const borderLine = '#E5E7EB';

      // Status Colors
      const passColor = '#10B981';
      const partialColor = '#F59E0B';
      const failColor = '#EF4444';

      // ── Header Banner ──
      doc.rect(0, 0, 595.28, 90).fill('#0B0F19');

      // SecureGuard Brand Title
      doc.fillColor('#FFFFFF')
         .fontSize(22)
         .font('Helvetica-Bold')
         .text('SecureGuard', 40, 24);

      doc.fillColor('#9CA3AF')
         .fontSize(10)
         .font('Helvetica')
         .text('Automated Security & Compliance Platform', 40, 50);

      // Framework Badge (Right Top)
      doc.rect(420, 25, 135, 36).fill(primaryColor);
      doc.fillColor('#FFFFFF')
         .fontSize(12)
         .font('Helvetica-Bold')
         .text(`${reportData.report.framework}`, 420, 31, { width: 135, align: 'center' });
      doc.fontSize(8)
         .font('Helvetica')
         .text('COMPLIANCE REPORT', 420, 47, { width: 135, align: 'center' });

      let y = 110;

      // ── Report Metadata Box ──
      doc.rect(40, y, 515.28, 55).fillAndStroke('#F9FAFB', borderLine);
      
      doc.fillColor(textDim).fontSize(8).font('Helvetica-Bold');
      doc.text('REPORT NAME:', 55, y + 10);
      doc.text('REPOSITORY:', 55, y + 25);
      doc.text('ASSESSMENT PERIOD:', 55, y + 40);

      doc.fillColor(textMain).fontSize(8).font('Helvetica');
      doc.text(reportData.report.name, 150, y + 10);
      doc.text(`${reportData.report.repositoryFullName} (${reportData.report.platform || 'git'})`, 150, y + 25);
      
      const fromStr = new Date(reportData.report.assessmentPeriod.from).toLocaleDateString();
      const toStr = new Date(reportData.report.assessmentPeriod.to).toLocaleDateString();
      doc.text(`${fromStr}  to  ${toStr}`, 150, y + 40);

      const genDateStr = new Date(reportData.report.generatedAt).toLocaleString();
      doc.fillColor(textDim).text(`GENERATED: ${genDateStr}`, 360, y + 10, { width: 180, align: 'right' });

      y += 75;

      // ── Executive Summary Section ──
      doc.fillColor(textMain).fontSize(14).font('Helvetica-Bold').text('Executive Summary', 40, y);
      y += 20;

      // Compliance Score Box
      const score = reportData.summary.score;
      let scoreColor = passColor;
      if (score < 60) scoreColor = failColor;
      else if (score < 80) scoreColor = partialColor;

      doc.rect(40, y, 160, 95).fillAndStroke('#F3F4F6', borderLine);
      doc.fillColor(textDim).fontSize(9).font('Helvetica-Bold').text('COMPLIANCE SCORE', 50, y + 12);
      
      doc.fillColor(scoreColor).fontSize(36).font('Helvetica-Bold').text(`${score}`, 50, y + 28);
      doc.fillColor(textDim).fontSize(12).font('Helvetica').text('/100', 125, y + 48);

      let scoreRating = 'EXCELLENT';
      if (score < 50) scoreRating = 'CRITICAL RISK';
      else if (score < 70) scoreRating = 'NEEDS ATTENTION';
      else if (score < 85) scoreRating = 'SATISFACTORY';

      doc.fillColor(scoreColor).fontSize(9).font('Helvetica-Bold').text(scoreRating, 50, y + 74);

      // Findings Breakdown Box
      doc.rect(215, y, 160, 95).fillAndStroke('#F3F4F6', borderLine);
      doc.fillColor(textDim).fontSize(9).font('Helvetica-Bold').text('VULNERABILITIES DETECTED', 225, y + 12);
      
      doc.fillColor(textMain).fontSize(24).font('Helvetica-Bold').text(`${reportData.summary.totalFindings}`, 225, y + 28);
      
      doc.fillColor(failColor).fontSize(8).font('Helvetica-Bold')
         .text(`Critical: ${reportData.summary.critical}`, 225, y + 58);
      doc.fillColor(partialColor).fontSize(8).font('Helvetica-Bold')
         .text(`High: ${reportData.summary.high}`, 285, y + 58);
      doc.fillColor('#D97706').fontSize(8).font('Helvetica-Bold')
         .text(`Medium: ${reportData.summary.medium}`, 225, y + 74);
      doc.fillColor(passColor).fontSize(8).font('Helvetica-Bold')
         .text(`Low: ${reportData.summary.low}`, 285, y + 74);

      // Controls Breakdown Box
      doc.rect(390, y, 165.28, 95).fillAndStroke('#F3F4F6', borderLine);
      doc.fillColor(textDim).fontSize(9).font('Helvetica-Bold').text('CONTROL STATUS', 400, y + 12);
      
      doc.fillColor(passColor).fontSize(9).font('Helvetica-Bold')
         .text(`PASSED: ${reportData.summary.passedControls}`, 400, y + 32);
      doc.fillColor(partialColor).fontSize(9).font('Helvetica-Bold')
         .text(`PARTIAL: ${reportData.summary.partialControls}`, 400, y + 50);
      doc.fillColor(failColor).fontSize(9).font('Helvetica-Bold')
         .text(`FAILED: ${reportData.summary.failedControls}`, 400, y + 68);

      y += 115;

      // ── Compliance Controls Table Header ──
      doc.fillColor(textMain).fontSize(14).font('Helvetica-Bold').text('Compliance Controls Evaluation', 40, y);
      y += 20;

      // Table Header Row
      doc.rect(40, y, 515.28, 22).fill('#1E293B');
      doc.fillColor('#FFFFFF').fontSize(8).font('Helvetica-Bold');
      doc.text('ID & CONTROL NAME', 48, y + 7);
      doc.text('CATEGORY', 240, y + 7);
      doc.text('STATUS', 380, y + 7);
      doc.text('FINDINGS', 480, y + 7);

      y += 22;

      // Render Controls
      reportData.controls.forEach(ctrl => {
        if (y > 700) {
          doc.addPage();
          y = 50;
        }

        let bg = '#FFFFFF';
        if (ctrl.status === 'FAIL') bg = '#FEF2F2';
        else if (ctrl.status === 'PARTIAL') bg = '#FFFBEB';

        doc.rect(40, y, 515.28, 48).fillAndStroke(bg, borderLine);

        // Control ID & Name
        doc.fillColor(textMain).fontSize(9).font('Helvetica-Bold').text(`${ctrl.id} - ${ctrl.name}`, 48, y + 6, { width: 185 });
        doc.fillColor(textDim).fontSize(7.5).font('Helvetica').text(ctrl.description, 48, y + 20, { width: 185, height: 24 });

        // Category
        doc.fillColor(textDim).fontSize(8).font('Helvetica').text(ctrl.category, 240, y + 10, { width: 130 });

        // Status Badge
        let badgeColor = passColor;
        if (ctrl.status === 'FAIL') badgeColor = failColor;
        else if (ctrl.status === 'PARTIAL') badgeColor = partialColor;

        doc.rect(380, y + 10, 80, 18).fill(badgeColor);
        doc.fillColor('#FFFFFF').fontSize(8).font('Helvetica-Bold').text(ctrl.status, 380, y + 14, { width: 80, align: 'center' });

        // Findings count
        doc.fillColor(textMain).fontSize(9).font('Helvetica-Bold').text(`${ctrl.findingsCount}`, 495, y + 14);

        y += 52;
      });

      y += 15;

      // ── Security Findings Section ──
      if (y > 650) {
        doc.addPage();
        y = 50;
      }

      doc.fillColor(textMain).fontSize(14).font('Helvetica-Bold').text('Detailed Security Findings', 40, y);
      y += 20;

      if (!reportData.findings || reportData.findings.length === 0) {
        doc.rect(40, y, 515.28, 40).fillAndStroke('#ECFDF5', '#A7F3D0');
        doc.fillColor('#065F46').fontSize(10).font('Helvetica-Bold').text('✓ No Open Security Vulnerabilities Detected', 55, y + 13);
        y += 55;
      } else {
        // Table Header
        doc.rect(40, y, 515.28, 20).fill('#1E293B');
        doc.fillColor('#FFFFFF').fontSize(8).font('Helvetica-Bold');
        doc.text('SEVERITY', 48, y + 6);
        doc.text('TITLE & FILE LOCATION', 120, y + 6);
        doc.text('CWE', 440, y + 6);
        doc.text('STATUS', 495, y + 6);
        y += 20;

        reportData.findings.forEach(f => {
          if (y > 710) {
            doc.addPage();
            y = 50;
          }

          doc.rect(40, y, 515.28, 38).fillAndStroke('#FFFFFF', borderLine);

          let sevColor = passColor;
          const s = (f.severity || '').toLowerCase();
          if (s === 'critical') sevColor = failColor;
          else if (s === 'high') sevColor = partialColor;
          else if (s === 'medium') sevColor = '#D97706';

          doc.rect(48, y + 8, 58, 16).fill(sevColor);
          doc.fillColor('#FFFFFF').fontSize(7.5).font('Helvetica-Bold').text(s.toUpperCase(), 48, y + 11, { width: 58, align: 'center' });

          doc.fillColor(textMain).fontSize(8.5).font('Helvetica-Bold').text(f.title, 120, y + 6, { width: 310 });
          doc.fillColor(textDim).fontSize(7.5).font('Helvetica').text(`${f.filePath}:${f.lineStart}`, 120, y + 20, { width: 310 });

          doc.fillColor(textDim).fontSize(8).font('Helvetica').text(f.cweId || 'N/A', 440, y + 12);
          doc.fillColor(textMain).fontSize(8).font('Helvetica-Bold').text(f.status.toUpperCase(), 495, y + 12);

          y += 42;
        });
      }

      y += 15;

      // ── Remediation Recommendations Section ──
      if (y > 650) {
        doc.addPage();
        y = 50;
      }

      doc.fillColor(textMain).fontSize(14).font('Helvetica-Bold').text('Prioritized Remediation Recommendations', 40, y);
      y += 20;

      reportData.recommendations.forEach(rec => {
        if (y > 710) {
          doc.addPage();
          y = 50;
        }

        doc.rect(40, y, 515.28, 45).fillAndStroke('#F8FAFC', borderLine);
        doc.fillColor(primaryColor).fontSize(9).font('Helvetica-Bold').text(`[${rec.priority}] ${rec.title}`, 50, y + 8);
        doc.fillColor(textDim).fontSize(8).font('Helvetica').text(rec.action, 50, y + 22, { width: 495 });

        y += 52;
      });

      y += 15;

      // ── Limitations & Legal Disclaimer ──
      if (y > 650) {
        doc.addPage();
        y = 50;
      }

      doc.fillColor(textMain).fontSize(12).font('Helvetica-Bold').text('Assessment Scope & Limitations', 40, y);
      y += 16;

      reportData.limitations.forEach(lim => {
        doc.fillColor(textDim).fontSize(8).font('Helvetica').text(`• ${lim}`, 45, y, { width: 505 });
        y += 14;
      });

      y += 15;
      doc.rect(40, y, 515.28, 45).fillAndStroke('#F3F4F6', '#D1D5DB');
      doc.fillColor('#4B5563').fontSize(7.5).font('Helvetica-Oblique').text(reportData.disclaimer, 50, y + 8, { width: 495 });

      // Add Page Numbers Footer to All Pages
      const range = doc.bufferedPageRange();
      for (let i = range.start; i < range.start + range.count; i++) {
        doc.switchToPage(i);
        doc.fillColor('#9CA3AF').fontSize(8).font('Helvetica');
        doc.text(
          `SecureGuard Security Assessment Report  |  Page ${i + 1} of ${range.count}`,
          40,
          800,
          { align: 'center', width: 515.28 }
        );
      }

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}

module.exports = {
  generateCompliancePdf
};
