// utils/salary.js
/**
 * Fungsi untuk menghitung gaji berdasarkan jam kerja dan jenis pekerjaan.
 * Mirip dengan fungsi PHP calculateSalary.
 *
 * @param {number} jamKerja Jumlah jam kerja.
 * @param {string} jenisPekerjaan Jenis pekerjaan ('flyer' atau lainnya).
 * @returns {number} Total gaji yang dihitung.
 */
function calculateSalary(jamKerja, jenisPekerjaan) {
  if (jenisPekerjaan === "flyer") {
    return 5000; // Gaji tetap untuk jenis pekerjaan 'flyer'
  } else {
    // Logika perhitungan gaji berdasarkan jam kerja untuk jenis pekerjaan selain 'flyer'
    if (jamKerja < 12) {
      return 20000; // Gaji untuk jam kerja kurang dari 12 jam
    } else if (jamKerja < 24) {
      return 15000; // Gaji untuk jam kerja antara 12 dan 24 jam
    } else {
      return 10000; // Gaji untuk jam kerja 24 jam atau lebih
    }
  }
}

module.exports = {
  calculateSalary,
};
