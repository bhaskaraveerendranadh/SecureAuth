const pool = require('./config/db');

async function checkDB() {
    try {
        const [rows] = await pool.execute('SELECT * FROM breach_data');
        console.log('Breach data count:', rows.length);
        if (rows.length === 0) {
            console.log('Table is empty. Run schema.sql or insert data.');
        } else {
            console.log(rows);
        }
    } catch (err) {
        console.error(err);
    } finally {
        process.exit();
    }
}
checkDB();
