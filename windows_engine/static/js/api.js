function display_psscan(evidence_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/psscan/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                          <th>Offset(V)</th>
                          <th>CreateTime</th>
                          <th>ExitTime</th>
                          <th>Handles</th>
                          <th>PID</th>
                          <th>PPID</th>
                          <th>ImageFileName</th>
                          <th>SessionId</th>
                          <th>Threads</th>
                          <th>Wow64</th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data,
        aoColumns: [
          { data: "Offset(V)" },
          { data: "CreateTime" },
          { data: "ExitTime" },
          { data: "Handles" },
          { data: "PID" },
          { data: "PPID" },
          { data: "ImageFileName" },
          { data: "SessionId" },
          { data: "Threads" },
          { data: "Wow64" },
        ],
        aLengthMenu: [
          [25, 50, 75, -1],
          [25, 50, 75, "All"],
        ],
        iDisplayLength: 25,
        searchBuilder: true,
      });
      artefact_datatable.searchBuilder
        .container()
        .prependTo($(artefact_datatable.table().container()));
      $("#artefacts_source_title").text("Process Scan");
      $("#artefacts_modal").modal("show");
    },
    error: function (xhr, status, error) {
      if (xhr.status === 404) {
        toastr.warning("Psscan is not available on this image.");
      } else {
        toastr.error(xhr.status);
      }
    },
  });
}

function display_thrdscan(evidence_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/thrdscan/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                          <th>Offset</th>
                          <th>CreateTime</th>
                          <th>ExitTime</th>
                          <th>PID</th>
                          <th>TID</th>
                          <th>StartAddress</th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data,
        aoColumns: [
          { data: "Offset" },
          { data: "CreateTime" },
          { data: "ExitTime" },
          { data: "PID" },
          { data: "TID" },
          { data: "StartAddress" },
        ],
        aLengthMenu: [
          [25, 50, 75, -1],
          [25, 50, 75, "All"],
        ],
        iDisplayLength: 25,
        searchBuilder: true,
      });
      artefact_datatable.searchBuilder
        .container()
        .prependTo($(artefact_datatable.table().container()));
      $("#artefacts_source_title").text("Thread Scan");
      $("#artefacts_modal").modal("show");
    },
    error: function (xhr, status, error) {
      if (xhr.status === 404) {
        toastr.warning("ThreadScan result is not available on this image.");
      } else {
        toastr.error(xhr.status);
      }
    },
  });
}

function display_sids(evidence_id, process_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/sids/${process_id}/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                          <th>Process</th>
                          <th>Name</th>
                          <th>SID</th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data,
        aoColumns: [{ data: "Process" }, { data: "Name" }, { data: "SID" }],
        aLengthMenu: [
          [25, 50, 75, -1],
          [25, 50, 75, "All"],
        ],
        iDisplayLength: 25,
        searchBuilder: true,
      });
      artefact_datatable.searchBuilder
        .container()
        .prependTo($(artefact_datatable.table().container()));
      $("#artefacts_source_title").text("Security IDs");
      $("#artefacts_modal").modal("show");
    },
    error: function (xhr, status, error) {
      if (xhr.status === 404) {
        toastr.warning("Security IDs are not available on this memory image.");
      } else {
        toastr.error(`An error occured : ${xhr.status}`);
      }
    },
  });
}

function display_mftscan(evidence_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/mftscan/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%">
          <thead>
            <tr>
              <th>Record Number</th>
              <th>Record Type</th>
              <th>MFT Type</th>
              <th>Filename</th>
              <th>Created</th>
              <th>Modified</th>
              <th>Accessed</th>
              <th>Updated</th>
              <th>Permissions</th>
              <th>Link Count</th>
              <th>Attribute Type</th>
              <th>Offset</th>
            </tr>
          </thead>
        </table>`,
      );
      let flattenedData = data.artefacts.flatMap((item) =>
        [item].concat(
          item.__children.map((child) => ({
            ...child,
            ParentRecord: item["Record Number"],
          })),
        ),
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: flattenedData,
        aoColumns: [
          { data: "Record Number" },
          { data: "Record Type" },
          { data: "MFT Type" },
          { data: "Filename" },
          { data: "Created" },
          { data: "Modified" },
          { data: "Accessed" },
          { data: "Updated" },
          { data: "Permissions" },
          { data: "Link Count" },
          { data: "Attribute Type" },
          { data: "Offset" },
        ],
        aLengthMenu: [
          [25, 50, 75, -1],
          [25, 50, 75, "All"],
        ],
        iDisplayLength: 25,
        searchBuilder: true,
      });
      artefact_datatable.searchBuilder
        .container()
        .prependTo($(artefact_datatable.table().container()));
      $("#artefacts_source_title").text("Master File Table Scan");
      $("#artefacts_modal").modal("show");
    },
    error: function (xhr, status, error) {
      if (xhr.status === 404) {
        toastr.warning("MFT scan is not available for this memory image.");
      } else {
        toastr.error(`An error occurred : ${xhr.status}`);
      }
    },
  });
}

function display_privs(evidence_id, process_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/privileges/${process_id}/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                        <th>Process</th>
                        <th>Privilege</th>
                        <th>Description</th>
                        <th>Value</th>
                        <th>Attributes</th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data,
        aoColumns: [
          { data: "Process" },
          { data: "Privilege" },
          { data: "Description" },
          { data: "Value" },
          { data: "Attributes" },
        ],
        aLengthMenu: [
          [25, 50, 75, -1],
          [25, 50, 75, "All"],
        ],
        iDisplayLength: 25,
        searchBuilder: true,
      });
      artefact_datatable.searchBuilder
        .container()
        .prependTo(artefact_datatable.table().container());
      $("#artefacts_source_title").text("Privileges");
      $("#artefacts_modal").modal("show");
    },
    error: function (xhr, status, error) {
      if (xhr.status === 404) {
        toastr.warning("Privileges are not available on this memory image.");
      } else {
        toastr.error(`An error occured : ${xhr.status}`);
      }
    },
  });
}

function display_envars(evidence_id, process_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/envars/${process_id}/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                        <th>Process</th>
                        <th>Block</th>
                        <th>Variable</th>
                        <th>Value</th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data,
        aoColumns: [
          { data: "Process" },
          { data: "Block" },
          { data: "Variable" },
          { data: "Value" },
        ],
        aLengthMenu: [
          [25, 50, 75, -1],
          [25, 50, 75, "All"],
        ],
        iDisplayLength: 25,
        searchBuilder: true,
      });
      artefact_datatable.searchBuilder
        .container()
        .prependTo(artefact_datatable.table().container());
      $("#artefacts_source_title").text("Environnement Variables ");
      $("#artefacts_modal").modal("show");
    },
    error: function (xhr, status, error) {
      if (xhr.status === 404) {
        toastr.warning(
          "Envars for this process are not available on this memory image.",
        );
      } else {
        toastr.error(`An error occured : ${xhr.status}`);
      }
    },
  });
}

function display_registry(evidence_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/registry/hivelist/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                        <th>Offset</th>
                        <th>FileFullPath</th>
                        <th>Action</th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data.artefacts,
        aoColumns: [
          { data: "Offset" },
          { data: "FileFullPath" },
          {
            mData: "id",
            mRender: function (id, type, row) {
              return generate_hive_download(row, data.evidence);
            },
          },
        ],
        aLengthMenu: [
          [25, 50, 75, -1],
          [25, 50, 75, "All"],
        ],
        iDisplayLength: 25,
        searchBuilder: false,
      });
      $("#artefacts_source_title").text("Registry Hive List");
      $("#artefacts_modal").modal("show");
    },
    error: function (xhr, status, error) {
      if (xhr.status === 404) {
        toastr.warning("Hivelist is not available on this memory image.");
      } else {
        toastr.error(`An error occured : ${xhr.status}`);
      }
    },
  });
}

function display_svcscan(evidence_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/svcscan/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                        <th>Offset</th>
                        <th>PID</th>
                        <th>Order</th>
                        <th>Name</th>
                        <th>Display</th>
                        <th>Binary</th>
                        <th>Start</th>
                        <th>State</th>
                        <th>Type</th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data.artefacts,
        aoColumns: [
          { data: "Offset" },
          { data: "PID" },
          { data: "Order" },
          { data: "Name" },
          { data: "Display" },
          { data: "Binary" },
          { data: "Start" },
          { data: "State" },
          { data: "Type" },
        ],
        aLengthMenu: [
          [25, 50, 75, -1],
          [25, 50, 75, "All"],
        ],
        iDisplayLength: 25,
        searchBuilder: true,
      });
      artefact_datatable.searchBuilder
        .container()
        .prependTo(artefact_datatable.table().container());
      $("#artefacts_modal").modal("show");
      $("#artefacts_source_title").text("Service Scan");
    },
    error: function (xhr, status, error) {
      if (xhr.status === 404) {
        toastr.warning("Services are not available on this memory image.");
      } else {
        toastr.error(`An error occured : ${xhr.status}`);
      }
    },
  });
}

function display_dlllist(evidence_id, process_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/dlllist/${process_id}/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                        <th>Process</th>
                        <th>Base</th>
                        <th>Name</th>
                        <th>Path</th>
                        <th>LoadTime</th>
                        <th>Size</th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data,
        aoColumns: [
          { data: "Process" },
          { data: "Base" },
          { data: "Name" },
          { data: "Path" },
          { data: "LoadTime" },
          { data: "Size" },
        ],
        aLengthMenu: [
          [25, 50, 75, -1],
          [25, 50, 75, "All"],
        ],
        iDisplayLength: 25,
        searchBuilder: true,
      });
      artefact_datatable.searchBuilder
        .container()
        .prependTo(artefact_datatable.table().container());
      $("#artefacts_modal").modal("show");
      $("#artefacts_source_title").text("DllList");
    },
    error: function (xhr, _status, error) {
      if (xhr.status === 404) {
        toastr.warning("Dlllist is not available");
      } else {
        toastr.error(`An error occured : ${xhr.status}`);
      }
    },
  });
}

function display_filescan(evidence_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/filescan/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                        <th>Offset</th>
                        <th>Name</th>
                        <th>Size</th>
                        <th>Action</th>
                      </tr>
                  </thead>
              </table>`,
      );

      artefacts_datatable = $("#artefacts_datatable").DataTable({
        aaData: data.artefacts,
        aoColumns: [
          { data: "Offset" },
          { data: "Name" },
          { data: "Size" },
          {
            mData: "id",
            mRender: function (id, type, row) {
              return generate_file_download_btn(row);
            },
          },
        ],
        aLengthMenu: [
          [25, 50, 75],
          [25, 50, 75],
        ],
        iDisplayLength: 25,
        searchBuilder: true,
        drawCallback: function () {
          $(".btn-dump-file")
            .off("click")
            .on("click", function () {
              file_id = $(this).attr("id");
              dump_file(evidence_id, file_id);
            });
        },
      });
      artefacts_datatable.searchBuilder
        .container()
        .prependTo(artefacts_datatable.table().container());
      $("#artefacts_modal").modal("show");
    },
    error: function (xhr, status, error) {
      if (xhr.status === 404) {
        toastr.warning("Filescan is not available for this memory dump");
      } else {
        toastr.error(`An error occured : ${xhr.status}`);
      }
    },
  });
}

function display_network(evidence_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/netstat/`,
    dataType: "json",
    success: function (data) {
      $("#netstat_datatable").DataTable().destroy();
      try {
        netstat_data = $("#netstat_datatable").DataTable({
          aaData: data.artefacts,
          aoColumns: [
            { data: "Proto" },
            { data: "LocalAddr" },
            { data: "LocalPort" },
            { data: "ForeignAddr" },
            { data: "ForeignPort" },
            { data: "State" },
            { data: "Offset" },
            { data: "Created" },
            { data: "Owner" },
          ],
          aLengthMenu: [
            [5, 10, 50, -1],
            [5, 10, 50, "All"],
          ],
          iDisplayLength: 5,
          searchBuilder: true,
        });
        netstat_data.searchBuilder
          .container()
          .prependTo(netstat_data.table().container());
      } catch {
        toastr.warning("An error occured when loading data for 'netstat'.");
      }
      $("#netstat_datatable").show("fast");
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });

  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/netscan/`,
    dataType: "json",
    success: function (data) {
      $("#netscan_datatable").DataTable().destroy();
      try {
        netscan_data = $("#netscan_datatable").DataTable({
          aaData: data.artefacts,
          aoColumns: [
            { data: "Proto" },
            { data: "LocalAddr" },
            { data: "LocalPort" },
            { data: "ForeignAddr" },
            { data: "ForeignPort" },
            { data: "State" },
            { data: "Offset" },
            { data: "Created" },
            { data: "Owner" },
          ],
          aLengthMenu: [
            [5, 10, 50, -1],
            [5, 10, 50, "All"],
          ],
          iDisplayLength: 5,
          searchBuilder: true,
        });
        netscan_data.searchBuilder
          .container()
          .prependTo(netscan_data.table().container());
      } catch {
        toastr.warning("An error occured when loading data for 'netscan'.");
      }

      $("#netscan_datatable").show();
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });

  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/netgraph/`,
    dataType: "json",
    success: function (data) {
      if (data.artefacts !== null) {
        generate_network_visualisation(data);
      }
    },
  });
  $("#network").modal("show");
}

function display_timeline(evidence_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/timeline/`,
    dataType: "json",
    success: function (data) {
      theme = document
        .querySelector("[data-bs-theme]")
        .getAttribute("data-bs-theme");
      let seriesData = [];
      if (data.artefacts) {
        data.artefacts.forEach((item) => {
          seriesData.push({ x: item[0], y: item[1] });
        });
      }
      var options = {
        theme: {
          mode: theme,
          palette: "palette1",
          monochrome: {
            enabled: true,
            color: "#9a0000",
            shadeTo: "light",
            shadeIntensity: 0.65,
          },
        },
        series: [
          {
            data: seriesData,
          },
        ],
        chart: {
          background: theme === "dark" ? "#101418" : "#fff",
          type: "area",
          stacked: false,
          height: 500,
          zoom: {
            type: "x",
            enabled: true,
            autoScaleYaxis: true,
          },
          events: {
            markerClick: function (
              event,
              chartContext,
              { seriesIndex, dataPointIndex, config },
            ) {
              var timestamp =
                chartContext.w.config.series[seriesIndex].data[dataPointIndex]
                  .x;
              display_timeliner(evidence_id, timestamp);
            },
            zoomed: function (chartContext, { xaxis, yaxis }) {
              display_timeliner(
                evidence_id,
                data.artefacts[xaxis.min - 1][0],
                data.artefacts[xaxis.max - 1][0],
              );
            },
          },
        },
        dataLabels: {
          enabled: false,
        },
        markers: {
          size: 0,
        },
        title: {
          text: "Timeline of events",
          align: "left",
        },
        fill: {
          type: "gradient",
          gradient: {
            shadeIntensity: 1,
            inverseColors: false,
            opacityFrom: 0.5,
            opacityTo: 0,
            stops: [0, 70, 80, 100],
          },
        },
        yaxis: {
          tickAmount: 4,
          labels: {
            formatter: function (val) {
              return val.toFixed(0);
            },
          },
          title: {
            text: "Event Count",
          },
        },
        xaxis: {},
        tooltip: {
          shared: false,
          y: {
            formatter: function (val) {
              return val.toFixed(0);
            },
          },
        },
      };

      var chart = new ApexCharts(document.querySelector("#timeline"), options);
      chart.render();
    },
    error: function (xhr, status, error) {
      toastr.warning("The Timeline is unavailable");
    },
  });
}

function display_sessions(evidence_id, process_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/sessions/${process_id}/`,
    dataType: "json",
    success: function (data) {
      $(".p_session_username").text(data[0]["User Name"]);
    },
    error: function (xhr, status, error) {
      $(".p_session_username").text("Unavailable");
    },
  });
}

function display_cmdline(evidence_id, process_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/cmdline/${process_id}/`,
    dataType: "json",
    success: function (data) {
      $(".p_cmdline").text(data[0].Args);
    },
    error: function (xhr, status, error) {
      $(".p_cmdline").text("Unavailable");
    },
  });
}

function display_timeliner(evidence_id, timestamp_min, timestamp_max) {
  $("#timeline_datatable").DataTable().destroy();
  timeline_datatable = $("#timeline_datatable").DataTable({
    processing: true,
    serverSide: true,
    ajax: {
      url: `${baseURL}/${evidence_id}/timeliner/?timestamp_min=${timestamp_min}&timestamp_max=${timestamp_max}`,
      type: "GET",
      data: function (d) {
        d.timestamp_min = timestamp_min;
        d.timestamp_max = timestamp_max;
      },
    },
    aoColumns: [
      { data: "Plugin" },
      { data: "Description", width: "40%" },
      { data: "Created Date" },
      { data: "Accessed Date" },
      { data: "Changed Date" },
      { data: "Modified Date" },
    ],
    aLengthMenu: [
      [25, 50, 75],
      [25, 50, 75],
    ],
    iDisplayLength: 25,
    searchBuilder: true,
  });
  timeline_datatable.searchBuilder
    .container()
    .prependTo(timeline_datatable.table().container());
}

function display_credentials(evidence_id) {
  /*
    Get the hashdump, lsadump, cachedump data from the API and display them
    using the "build_credential_card" function from visualisation.js
  */
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/hashdump/`,
    dataType: "json",
    success: function (data) {
      if (data.artefacts && data.artefacts.length > 0) {
        $("#credentials_cards_1").empty();
        $("#credentials_cards_2").empty();
        $("#credentials_cards_3").empty();
        $.each(data.artefacts, function (_, value) {
          build_credential_card("Hashdump", value);
        });
      } else {
        $("#credentials_cards_1").html(
          `<i class="text-info">No Hash found for HashDump<i/>`,
        );
      }
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });

  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/cachedump/`,
    dataType: "json",
    success: function (data) {
      if (data.artefacts && data.artefacts.length > 0) {
        $.each(data, function (_, value) {
          build_credential_card("Cachedump", value);
        });
      } else {
        $("#credentials_cards_2").html(
          `<i class="text-info">No Hash found for CacheDump<i/>`,
        );
      }
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });

  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/lsadump/`,
    dataType: "json",
    success: function (data) {
      if (data.artefacts && data.artefacts.length > 0) {
        $.each(data, function (_, value) {
          build_credential_card("Lsadump", value);
        });
      } else {
        $("#credentials_card_3").html(
          `<i class="text-info">No Hash found for LsaDump<i/>`,
        );
      }
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });
  $("#credentials").modal("show");
}

function display_malfind(evidence_id) {
  /*
    Get the malfind data from the API and display them using the
    "build_malfind_process_card" function from visualisation.js
  */
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/malfind/`,
    dataType: "json",
    beforeSend: function () {
      $("#malfind_process_list").empty();
      $("#malfind_process_menu").show();
      $("#malfind_process_loading").show();
    },
    success: function (data, status, xhr) {
      if (data.artefacts && data.artefacts.length > 0) {
        $.each(data.artefacts, function (_, value) {
          build_malfind_process_card(value);
        });
      } else {
        $("#malfind_process_list").html(
          `<i class="text-info">Malfind did not return any results.</i>`,
        );
      }
    },
    complete: function (data) {
      $("#malfind_process_loading").hide();
      $("#malfind_process_list").show();
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred while fetching result : " + error);
    },
  });
}

function display_ldrmodules(evidence_id) {
  /*
    Get the ldrmodules data from the API and display them using datatables
  */
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/ldrmodules/`,
    dataType: "json",
    beforeSend: function () {
      $("#ir_artefacts_datatable").DataTable().destroy();
      $("#ir_artefacts_body").hide();
      $("#ir_details").show();
      $("#ir_artefacts_loading").show();
      $("#ir_artefacts_title").text("Process Modules");
    },
    success: function (data, status, xhr) {
      if (data.artefacts && data.artefacts.length > 0) {
        $("#ir_artefacts_body").html(
          `<table id="ir_artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
            >
                    <thead>
                        <tr>
                            <th>Base</th>
                            <th>Process</th>
                            <th>Pid</th>
                            <th>MappedPath</th>
                            <th>InInit</th>
                            <th>InLoad</th>
                            <th>InMem</th>
                        </tr>
                    </thead>
                </table>`,
        );
        ir_artefacts_datatable = $("#ir_artefacts_datatable").DataTable({
          aaData: data.artefacts,
          aoColumns: [
            { data: "Base" },
            { data: "Process" },
            { data: "Pid" },
            { data: "MappedPath" },
            { data: "InInit" },
            { data: "InLoad" },
            { data: "InMem" },
          ],
          aLengthMenu: [
            [25, 50, 75, -1],
            [25, 50, 75, "All"],
          ],
          iDisplayLength: 25,
          searchBuilder: true,
        });
        ir_artefacts_datatable.searchBuilder
          .container()
          .prependTo(ir_artefacts_datatable.table().container());
      } else {
        $("#ir_artefacts_body").html(
          "<i>Process modules data are not available</i>",
        );
      }
    },
    complete: function (data) {
      $("#ir_artefacts_loading").hide();
      $("#ir_artefacts_body").show();
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred while fetching the modules : " + error);
    },
  });
}

function display_kernel_modules(evidence_id) {
  /*
    Get the kernel_modules data from the API and display them using datatables
  */
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/modules/`,
    dataType: "json",
    beforeSend: function () {
      $("#ir_artefacts_datatable").DataTable().destroy();
      $("#ir_artefacts_body").hide();
      $("#ir_details").show();
      $("#ir_artefacts_loading").show();
      $("#ir_artefacts_title").text("Kernel Modules");
    },
    success: function (data, status, xhr) {
      if (data.artefacts && data.artefacts.length > 0) {
        $("#ir_artefacts_body").html(
          `<table id="ir_artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
            >
                    <thead>
                        <tr>
                            <th>Base</th>
                            <th>Name</th>
                            <th>Offset</th>
                            <th>Path</th>
                            <th>Size</th>
                        </tr>
                    </thead>
                </table>`,
        );
        ir_artefacts_datatable = $("#ir_artefacts_datatable").DataTable({
          aaData: data.artefacts,
          aoColumns: [
            { data: "Base" },
            { data: "Name" },
            { data: "Offset" },
            { data: "Path" },
            { data: "Size" },
          ],
          aLengthMenu: [
            [25, 50, 75, -1],
            [25, 50, 75, "All"],
          ],
          iDisplayLength: 25,
          searchBuilder: true,
        });
        ir_artefacts_datatable.searchBuilder
          .container()
          .prependTo(ir_artefacts_datatable.table().container());
      } else {
        $("#ir_artefacts_body").html("<i>Modules data are not available</i>");
      }
    },
    complete: function (data) {
      $("#ir_artefacts_loading").hide();
      $("#ir_artefacts_body").show();
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred while fetching the modules : " + error);
    },
  });
}

function display_ssdt(evidence_id) {
  /*
    Get the ssdt data from the API and display them using datatables
  */
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/ssdt/`,
    dataType: "json",
    beforeSend: function () {
      $("#ir_artefacts_datatable").DataTable().destroy();
      $("#ir_artefacts_body").hide();
      $("#ir_details").show();
      $("#ir_artefacts_loading").show();
      $("#ir_artefacts_title").text("Directory Table");
    },
    success: function (data, status, xhr) {
      if (data.artefacts && data.artefacts.length > 0) {
        $("#ir_artefacts_body").html(
          `<table id="ir_artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
            >
                    <thead>
                        <tr>
                            <th>Address</th>
                            <th>Index</th>
                            <th>Module</th>
                            <th>Symbol</th>
                        </tr>
                    </thead>
                </table>`,
        );
        ir_artefacts_datatable = $("#ir_artefacts_datatable").DataTable({
          aaData: data.artefacts,
          aoColumns: [
            { data: "Address" },
            { data: "Index" },
            { data: "Module" },
            { data: "Symbol" },
          ],
          aLengthMenu: [
            [25, 50, 75, -1],
            [25, 50, 75, "All"],
          ],
          iDisplayLength: 25,
          searchBuilder: true,
        });
        ir_artefacts_datatable.searchBuilder
          .container()
          .prependTo(ir_artefacts_datatable.table().container());
      } else {
        $("#ir_artefacts_body").html("<i>SSDT data are not available</i>");
      }
    },
    complete: function (data) {
      $("#ir_artefacts_loading").hide();
      $("#ir_artefacts_body").show();
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred while fetching the ssdt : " + error);
    },
  });
}

function display_driverirp(evidence_id) {
  /*
    Get the ssdt data from the API and display them using datatables
  */
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/driverirp/`,
    dataType: "json",
    beforeSend: function () {
      $("#ir_artefacts_datatable").DataTable().destroy();
      $("#ir_artefacts_body").hide();
      $("#ir_details").show();
      $("#ir_artefacts_loading").show();
      $("#ir_artefacts_title").text("Driver IRP");
    },
    success: function (data, status, xhr) {
      if (data.artefacts && data.artefacts.length > 0) {
        $("#ir_artefacts_body").html(
          `<table id="ir_artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
            >
                    <thead>
                        <tr>
                            <th>Address</th>
                            <th>Driver Name</th>
                            <th>IRP</th>
                            <th>Module</th>
                            <th>Offset</th>
                            <th>Symbol</th>
                        </tr>
                    </thead>
                </table>`,
        );
        ir_artefacts_datatable = $("#ir_artefacts_datatable").DataTable({
          aaData: data.artefacts,
          aoColumns: [
            { data: "Address" },
            { data: "Driver Name" },
            { data: "IRP" },
            { data: "Module" },
            { data: "Offset" },
            { data: "Symbol" },
          ],
          aLengthMenu: [
            [25, 50, 75, -1],
            [25, 50, 75, "All"],
          ],
          iDisplayLength: 25,
          searchBuilder: true,
        });
        ir_artefacts_datatable.searchBuilder
          .container()
          .prependTo(ir_artefacts_datatable.table().container());
      } else {
        $("#ir_artefacts_body").html(
          "<i>Driver IRP data are not available</i>",
        );
      }
    },
    complete: function (data) {
      $("#ir_artefacts_loading").hide();
      $("#ir_artefacts_body").show();
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred while fetching the driverirp : " + error);
    },
  });
}

function display_iat(evidence_id) {
  /*
    Get the ssdt data from the API and display them using datatables
  */
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/iat/`,
    dataType: "json",
    beforeSend: function () {
      $("#ir_artefacts_datatable").DataTable().destroy();
      $("#ir_artefacts_body").hide();
      $("#ir_details").show();
      $("#ir_artefacts_loading").show();
      $("#ir_artefacts_title").text("Driver IRP");
    },
    success: function (data, status, xhr) {
      if (data.artefacts && data.artefacts.length > 0) {
        $("#ir_artefacts_body").html(
          `<table id="ir_artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
            >
                    <thead>
                        <tr>
                            <th>Address</th>
                            <th>Bound</th>
                            <th>Function</th>
                            <th>Library</th>
                            <th>Name</th>
                            <th>PID</th>
                        </tr>
                    </thead>
                </table>`,
        );
        ir_artefacts_datatable = $("#ir_artefacts_datatable").DataTable({
          aaData: data.artefacts,
          aoColumns: [
            { data: "Address" },
            { data: "Bound" },
            { data: "Function" },
            { data: "Library" },
            { data: "Name" },
            { data: "PID" },
          ],
          aLengthMenu: [
            [25, 50, 75, -1],
            [25, 50, 75, "All"],
          ],
          iDisplayLength: 25,
          searchBuilder: true,
        });
        ir_artefacts_datatable.searchBuilder
          .container()
          .prependTo(ir_artefacts_datatable.table().container());
      } else {
        $("#ir_artefacts_body").html(
          "<i>Driver IRP data are not available</i>",
        );
      }
    },
    complete: function (data) {
      $("#ir_artefacts_loading").hide();
      $("#ir_artefacts_body").show();
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred while fetching the IAT : " + error);
    },
  });
}

function display_ads(evidence_id) {
  /*
    Get the ads data from the API and display them using datatables
  */
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/ads/`,
    dataType: "json",
    beforeSend: function () {
      $("#ir_artefacts_datatable").DataTable().destroy();
      $("#ir_artefacts_body").hide();
      $("#ir_details").show();
      $("#ir_artefacts_loading").show();
      $("#ir_artefacts_title").text("Alternate Data Streams");
    },
    success: function (data, status, xhr) {
      if (data.artefacts && data.artefacts.length > 0) {
        $("#ir_artefacts_body").html(
          `<table id="ir_artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
            >
                    <thead>
                        <tr>
                            <th>Offset</th>
                            <th>Record Number</th>
                            <th>Record Type</th>
                            <th>ADS Filename</th>
                            <th>Filename</th>
                            <th>MFT Type</th>
                            <th>Hexdump</th>
                            <th>Disasm</th>
                        </tr>
                    </thead>
                </table>`,
        );
        ir_artefacts_datatable = $("#ir_artefacts_datatable").DataTable({
          aaData: data.artefacts,
          aoColumns: [
            { data: "Offset" },
            { data: "Record Number" },
            { data: "Record Type" },
            { data: "ADS Filename" },
            { data: "Filename" },
            { data: "MFT Type" },
            {
              mData: "Hexdump",
              mRender: function (hexdump, type, row) {
                return ` <code><pre>${hexdump}</pre></code>`;
              },
            },
            {
              mData: "Disasm",
              mRender: function (disasm, type, row) {
                return ` <code><pre>${disasm}</pre></code>`;
              },
            },
          ],
          aLengthMenu: [
            [25, 50, 75, -1],
            [25, 50, 75, "All"],
          ],
          iDisplayLength: 25,
          searchBuilder: true,
        });
        ir_artefacts_datatable.searchBuilder
          .container()
          .prependTo(ir_artefacts_datatable.table().container());
      } else {
        $("#ir_artefacts_body").html("<i>ADS data are not available</i>");
      }
    },
    complete: function (data) {
      $("#ir_artefacts_loading").hide();
      $("#ir_artefacts_body").show();
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred while fetching the ads : " + error);
    },
  });
}

function display_mbrscan(evidence_id) {
  function formatChildRows(data) {
    const children = data.__children || [];
    let html = `<table cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;">
      <thead>
      <tr>
        <th>Bootable</th>
        <th>Bootcode MD5</th>
        <th>Disk Signature</th>
        <th>Full MBR MD5</th>
        <th>PartitionIndex</th>
        <th>PartitionType</th>
        <th>Potential MBR at Physical Offset</th>
        <th>SectorInSize</th>
      </tr>
      </thead>`;
    // Add headers or skip headers to jump straight into the data

    // Iterate over child objects to create table rows
    children.forEach((child) => {
      html += `<tr>
          <td>${child.Bootable}</td>
          <td>${child["Bootcode MD5"]}</td>
          <td>${child["Disk Signature"]}</td>
          <td>${child["Full MBR MD5"]}</td>
          <td>${child.PartitionIndex}</td>
          <td>${child.PartitionType}</td>
          <td>${child["Potential MBR at Physical Offset"]}</td>
          <td>${child.SectorInSize}</td>
        </tr>
        `;
    });
    html += "</table>";
    return html;
  }

  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/mbrscan/`,
    dataType: "json",
    beforeSend: function () {
      $("#ir_artefacts_datatable").DataTable().destroy();
      $("#ir_artefacts_body").hide();
      $("#ir_details").show();
      $("#ir_artefacts_loading").show();
      $("#ir_artefacts_title").text("Master Boot Record Scan");
    },

    success: function (data, status, xhr) {
      if (data.artefacts && data.artefacts.length > 0) {
        $("#ir_artefacts_body").html(
          `<table id="ir_artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
            >
                    <thead>
                        <tr>
                            <th></th>
                            <th>Bootable</th>
                            <th>Bootcode MD5</th>
                            <th>Disasm</th>
                            <th>Disk Signature</th>
                            <th>Full MBR MD5</th>
                            <th>Physical Offset</th>
                        </tr>
                    </thead>
                </table>`,
        );
        ir_artefacts_datatable = $("#ir_artefacts_datatable").DataTable({
          aaData: data.artefacts, // your API data (array of objects)
          aoColumns: [
            {
              className: "dt-control",
              orderable: false,
              data: null,
              defaultContent: "",
            },
            { data: "Bootable" },
            { data: "Bootcode MD5" },
            {
              mData: "Disasm",
              mRender: function (disasm, type, row) {
                return ` <code><pre>${disasm}</pre></code>`;
              },
            },
            { data: "Disk Signature" },
            { data: "Full MBR MD5" },
            { data: "Potential MBR at Physical Offset" },
            // ... other fields to match your objects
          ],
          order: [[1, "asc"]],
          aLengthMenu: [
            [25, 50, 75, -1],
            [25, 50, 75, "All"],
          ],
          iDisplayLength: 25,
          searchBuilder: true,
        });
        ir_artefacts_datatable.searchBuilder
          .container()
          .prependTo(ir_artefacts_datatable.table().container());
        $("#ir_artefacts_datatable tbody").on(
          "click",
          "td.dt-control",
          function () {
            var tr = $(this).closest("tr");
            var row = ir_artefacts_datatable.row(tr);

            if (row.child.isShown()) {
              // This row is already open - close it
              row.child.hide();
              tr.removeClass("shown");
            } else {
              // Open this row
              row.child(formatChildRows(row.data())).show();
              tr.addClass("shown");
            }
          },
        );
      } else {
        $("#ir_artefacts_body").html(
          "<i>Master BootRecord data are not available</i>",
        );
      }
    },
    complete: function (data) {
      $("#ir_artefacts_loading").hide();
      $("#ir_artefacts_body").show();
    },
  });
}

function generate_file_download_btn(data) {
  btn = document.createElement("i");
  btn.setAttribute("class", "fas fa-download btn-dump-file");
  btn.setAttribute("id", data.Offset);
  return btn.outerHTML;
}

function generate_hive_download(data, evidence_data) {
  if (data["File output"]) {
    link = document.createElement("a");
    link.setAttribute(
      "href",
      `/media/${evidence_data}/${encodeURIComponent(data["File output"])}`,
    );
    link.setAttribute("target", "_blank");
    link.setAttribute("class", "fas fa-download");
    return link.outerHTML;
  } else {
    return "N/A";
  }
}
