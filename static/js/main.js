document.addEventListener("DOMContentLoaded", function () {
    const today = new Date().toISOString().split("T")[0];
    document.getElementById("start").value = today;
    document.getElementById("end").value = today;
});
$(document).ready(function () {
    let table = $('#alerts-table').DataTable({
        ajax: {
            url: '/data',
            type: 'POST',
            data: function (d) {
                d.start = $('#start').val();
                d.end = $('#end').val();
            },
            dataSrc: 'data'
        },
        columns: [
            { data: 'id' },
            { data: 'ip' },
            { data: 'url' },
            { data: 'method' },
            { data: 'user_agent' },
            { data: 'attempts' },
            { data: 'created_at' }
        ],
        order: [[6, 'desc']],
    });

    $('#filter-form').on('submit', function (e) {
        e.preventDefault();
        table.ajax.reload();
    });
});
