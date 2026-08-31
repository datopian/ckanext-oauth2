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
              let value = `${data}`;
              if (row[1] === 'True') {
                value += `<div><span class="badge badge-danger">Guest</span> &nbsp;`;
              }
              let badgeClass = 'badge-success';
              switch (row[2]) {
                case 'pending':
                  badgeClass = 'badge-warning';
                  break;
                case 'approved':
                  badgeClass = 'badge-success';
                  break;
                case 'rejected':
                  badgeClass = 'badge-danger';
                  break;
              }
              value += `<span class="badge ${badgeClass}">${row[2]}</span></div>`;
              return value;
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
      var ERROR_CLASS = 'institution-choice__error';

      function field() {
        return jQuery('#field-institution');
      }

      function isGuest() {
        return jQuery('#affiliation-guest').is(':checked');
      }

      function clearError() {
        jQuery('.' + ERROR_CLASS).remove();
        jQuery('.institution-choice__field').removeClass('has-error');
      }

      function showError(message) {
        clearError();
        jQuery('.institution-choice__field')
          .addClass('has-error')
          .append('<span class="' + ERROR_CLASS + '"></span>')
          .find('.' + ERROR_CLASS)
          .text(message);
      }

      function sync() {
        var guest = isGuest();

        jQuery('.institution-choice__field').toggle(!guest);
        jQuery('#guest_user').val(guest ? 'True' : '');

        // Never set `required` here: select2 hides the real input, and the
        // browser skips constraint validation on hidden fields - the submit
        // button would just die silently. Validated on submit instead.
        field().removeAttr('required');

        if (guest) {
          clearError();
          // Drop any stale selection so a guest never submits an institution.
          if (field().data('select2')) {
            field().select2('val', '');
          } else {
            field().val('');
          }
        }
      }

      jQuery('input[name="affiliation"]').on('change', function () {
        clearError();
        sync();
      });

      field().on('change', clearError);

      // Block submit with a visible message when an institution is required
      // but not chosen. The server enforces this too; this is just so the
      // user sees it next to the field.
      jQuery('#user-edit-form').on('submit', function (event) {
        if (!isGuest() && !jQuery.trim(field().val() || '')) {
          event.preventDefault();
          showError(this.getAttribute('data-institution-required')
            || 'Please select your institution.');
          jQuery('#s2id_field-institution').find('.select2-choice').focus();
          return false;
        }
        clearError();
      });

      // Apply on load too: a returning guest arrives with the guest radio
      // already selected, and change alone never fires for them.
      sync();
    }
  };
});