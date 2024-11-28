this.ckan.module('review-user-table', function ($) {
  return {
    initialize: function () {
      $.fn.dataTable.ext.search.push(function (settings, data, dataIndex) {
        var dateString = data[1];
        var dateParts = dateString.split('T')[0].split('-');
        var date = new Date(dateParts[0], dateParts[1] - 1, dateParts[2]);

        // Get the current date and subtract the selected number of days or months
        var today = new Date();
        var daysAgo = new Date();

        var selectedValue = $('#date-filter-select').val();

        if (selectedValue === '3d') {
          daysAgo.setDate(today.getDate() - 3);
        } else if (selectedValue === '7d') {
          daysAgo.setDate(today.getDate() - 7);
        } else if (selectedValue === '1m') {
          daysAgo.setMonth(today.getMonth() - 1);
        } else {
          return true;
        }

        // Check if the date is within the selected range
        if (date >= daysAgo && date <= today) {
          return true;
        }

        return false;
      });

      var table = this.el.DataTable({
        initComplete: function () {
        },
        lengthChange: false,
        pageLength: 20,
        language: {
          paginate: {
            next: '»',
            previous: '«'
          }
        },
        columnDefs: [{
            targets: 0, // The index of the user column
            width: "45%",
            render: function (data, type, row, meta) {
              if (row[2] === 'pending') {
                return `${data}&nbsp;<span class="badge badge-warning">${row[2]}</span>`;
              } else if (row[2] === 'approved') {
                return `${data}&nbsp;<span class="badge badge-success">${row[2]}</span>`;
              } else if (row[2] === 'rejected') {
                return `${data}&nbsp;<span class="badge badge-danger">${row[2]}</span>`;
              } else {
                return `${data}&nbsp;<span class="badge badge-success">${row[2]}</span>`;
              }
            }
          },
          {
            targets: 1,
            render: function (data, type, row, meta) {
              // Format the date as YYYY-MM-DD
              var date = new Date(data);
              var month = '' + (date.getMonth() + 1);
              var day = '' + date.getDate();
              var year = date.getFullYear();

              if (month.length < 2) month = '0' + month;
              if (day.length < 2) day = '0' + day;

              return [year, month, day].join('-');
            }
          },

        ]
      });
      // Add a header with the total number of users and subscribed members
      var totalUsers = table.rows().count();
      table.column(0).header().textContent = 'User (' + totalUsers + ')';
    }
  };
});

this.ckan.module('guest-user-checkbox', function (jQuery) {
  return {
    initialize: function () {
      var el = this.el;
      var institutionEl = jQuery('.input-institution');
      el.change(function () {
        if (el.is(':checked')) {
          institutionEl.hide();
        } else {
          institutionEl.show();
        }
      });
    }
  };
});