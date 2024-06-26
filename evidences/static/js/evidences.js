var evidences;
var reconnectDelay = 10000;

function fetch_bucket_metadata(formData, params, callback) {
  AWS.config.update({
    accessKeyId: formData.dump_access_key_id,
    secretAccessKey: formData.dump_access_key,
    region: formData.dump_region,
  });

  var s3;
  if (formData.dump_source !== "AWS") {
    s3 = new AWS.S3({
      endpoint: formData.dump_endpoint,
      s3ForcePathStyle: true,
      signatureVersion: "v4",
      s3BucketEndpoint: true,
    });
  } else {
    s3 = new AWS.S3();
  }

  s3.headObject(params, function (err, data) {
    if (err) {
      toastr.error(
        "Can't fetch the metadata, make sure the provided credentials and authorizations are correct.",
      );
      $(".bind-progress").addClass("d-none");
      $("#bind_evidence_form").show();
      $("#bind-button").show();
      callback(true);
    } else {
      formData.dump_etag = data.ETag;
      formData.dump_name = params.Key;
      toastr.success("The evidence was found and accessible.");
      callback(false);
    }
  });
}

function bind_and_create_evidence(formData) {
  const url = new URL(formData.dump_url);
  if (url.protocol !== "s3:") {
    toastr.warning("The bucket s3 url is malformed.");
    return;
  } else {
    const match = formData.dump_url.match(/^s3:\/\/([^\/]+)\/(.+)$/);
    const params = {
      Bucket: match[1],
      Key: match[2],
    };
    $(".bind-progress").removeClass("d-none");
    $("#bind_evidence_form").hide();
    $("#bind-button").hide();
    fetch_bucket_metadata(formData, params, function (error) {
      if (error) {
        console.error("An error occurred: ", error);
        $(".bind-progress").addClass("d-none");
        $("#bind_evidence_form").show();
        $("#bind-button").show();
      } else {
        $.ajaxSetup({
          beforeSend: function (xhr, settings) {
            xhr.setRequestHeader(
              "X-CSRFToken",
              document.querySelector("[name=csrfmiddlewaretoken]").value,
            );
          },
        });
        $.ajax({
          type: "POST",
          url: `/api/evidences/bind/`,
          data: formData,
          dataType: "json",
          success: function (data) {
            toastr.success("Bind is a success.");
          },
          error: function (xhr, status, error) {
            toastr.error(error);
          },
        });
      }
      $("#modal_evidence_bind").modal("hide");
      $(".bind-progress").addClass("d-none");
      $("#bind_evidence_form").show();
      $("#bind-button").show();
    });
  }
}

function upload_and_create_evidence(bucket_id) {
  $.ajax({
    url: "/minio_secrets/",
    type: "GET",
    dataType: "json",
    success: function (data) {
      AWS.config.update({
        accessKeyId: data.endpoint.key_id,
        secretAccessKey: data.endpoint.key_password,
        region: data.endpoint.region,
      });
      var config;
      if (data.endpoint.url) {
        config = new AWS.S3({
          endpoint: data.endpoint.url,
          s3ForcePathStyle: true,
          signatureVersion: "v4",
          s3BucketEndpoint: true,
        });
      } else {
        config = new AWS.S3({
          s3ForcePathStyle: true,
          signatureVersion: "v4",
        });
      }

      const s3 = config;
      const fileChooser = document.getElementById("file-chooser");
      const file = fileChooser.files[0];
      if (file) {
        const uploader = s3.upload({
          Bucket: bucket_id,
          Key: file.name,
          Body: file,
        });

        uploader.on("httpUploadProgress", function (evt) {
          $(".upload-progress").removeClass("d-none");
          $("#evidence_form").hide();
          $("#upload-button").hide();
          $("#upload-progress").text(
            parseInt((evt.loaded * 100) / evt.total) + "%",
          );
        });

        uploader.send(function (err, data) {
          fileChooser.value = "";
          document.getElementById("upload-progress").innerHTML = "";
          if (err) {
            toastr.error("Error when uploading : " + err);
          }
          if (data) {
            toastr.success("Upload Success");
            create_evidence(file.name, data.ETag);
          }
          $("#modal_evidence_create").modal("hide");
          $(".upload-progress").addClass("d-none");
          $("#evidence_form").show();
          $("#upload-button").show();
          clear_form();
        });
      } else {
        toastr.warning("Nothing to upload");
      }
    },
    error: function (xhr, status, error) {
      toastr.error("The bucket S3 appliance can't be reached: " + error);
    },
  });
}

function get_evidences(case_id) {
  var url = "/api/evidences/";
  if (case_id) {
    url = `/api/evidences/case/${case_id}`;
  }
  $.ajax({
    url: url,
    method: "GET",
    contentType: "application/json",
  }).done(function (data) {
    $("#evidences").DataTable().destroy();
    evidences = $("#evidences").DataTable({
      rowCallback: function (row, data, index) {
        $(row).attr("value", data.dump_id);
        $(row).attr("id", data.dump_id);
        if (data.dump_status === 100) {
          $(row).removeClass("not-completed");
          $(row).addClass("completed");
        } else {
          $(row).removeClass("completed");
          $(row).addClass("not-completed");
        }
      },
      aaData: data,
      aoColumns: [
        {
          mData: "dump_name",
          sClass: "align-middle",
          mRender: function (dump_name, type, row) {
            div = document.createElement("small");
            div.setAttribute(
              "class",
              "d-flex fw-semibold text-danger-emphasis bg-danger-subtle border border-danger-subtle rounded-2 align-items-center",
            );
            logo = document.createElement("i");
            code = document.createElement("code");
            logo.setAttribute("class", "fas fa-memory m-2");
            code.textContent = dump_name;
            div.appendChild(logo);
            div.appendChild(code);

            if (row.dump_status != "100") {
              div.setAttribute(
                "class",
                "d-flex fw-semibold text-white-emphasis bg-white-subtle border border-white-subtle rounded-2 align-items-center",
              );
              $(code).addClass("text-muted");
            }

            return div.outerHTML;
          },
        },
        {
          mData: "dump_etag",
          sClass: "align-middle",
          mRender: function (dump_etag, type, row) {
            div = document.createElement("small");
            div.setAttribute(
              "class",
              "d-flex px-1 py-1 fw-semibold text-primary-emphasis bg-primary-subtle border border-primary-subtle rounded-2 align-items-center",
            );
            span = document.createElement("span");
            span.textContent = dump_etag;
            div.appendChild(span);
            if (row.dump_status != "100") {
              div.setAttribute(
                "class",
                "d-flex px-1 py-1 fw-semibold text-white-emphasis bg-white-subtle border border-white-subtle rounded-2 align-items-center",
              );
              span.setAttribute("class", "text-muted");
            }
            return div.outerHTML;
          },
        },
        {
          mData: "dump_os",
          sClass: "align-middle",
          mRender: function (dump_os, type, row) {
            div = document.createElement("small");
            logo = document.createElement("i");
            span = document.createElement("span");
            if (dump_os == "Windows") {
              div.setAttribute(
                "class",
                "d-flex px-0 py-0 fw-semibold text-info-emphasis bg-info-subtle border border-info-subtle rounded-2 align-items-center",
              );
              logo.setAttribute("class", "fab fa-windows m-2");
              span.setAttribute("class", "text-info");
            } else {
              div.setAttribute(
                "class",
                "d-flex px-0 py-0 fw-semibold text-purple-emphasis bg-purple-subtle border border-purple-subtle rounded-2 align-items-center",
              );
              logo.setAttribute("class", "fab fa-linux m-2");
              span.setAttribute("class", "text-purple");
            }
            span.textContent = dump_os;
            div.appendChild(logo);
            div.appendChild(span);

            if (row.dump_status != "100") {
              div.setAttribute(
                "class",
                "d-flex px-0 py-0 fw-semibold text-white-emphasis bg-white-subtle border border-white-subtle rounded-2 align-items-center",
              );
              span.setAttribute("class", "text-muted");
            }
            return div.outerHTML;
          },
        },
        {
          mData: "dump_linked_case_name",
          sClass: "align-middle",
          mRender: function (dump_linked_case_name, type, row) {
            div = document.createElement("small");

            div.setAttribute(
              "class",
              "d-flex fw-semibold text-white-emphasis bg-white-subtle border border-white-subtle rounded-2 align-items-center",
            );
            logo = document.createElement("i");
            span = document.createElement("span");
            logo.setAttribute("class", "fas fa-suitcase m-2");
            span.textContent = dump_linked_case_name;
            div.appendChild(logo);
            div.appendChild(span);
            if (row.dump_status != "100") {
              div.setAttribute(
                "class",
                "d-flex fw-semibold text-white-emphasis bg-white-subtle border border-white-subtle rounded-2 align-items-center",
              );
              span.setAttribute("class", "text-muted");
            }
            return div.outerHTML;
          },
        },
        {
          mData: "dump_status",
          sClass: "align-middle",
          mRender: function (dump_status, type) {
            div = document.createElement("small");

            div.setAttribute(
              "class",
              "d-flex fw-semibold text-white-emphasis bg-white-subtle border border-white-subtle rounded-2 align-items-center",
            );
            logo = document.createElement("i");
            span = document.createElement("span");
            span.textContent = dump_status;
            div.appendChild(logo);
            div.appendChild(span);

            if (dump_status == "100") {
              div.setAttribute(
                "class",
                "d-flex fw-semibold text-success-emphasis bg-success-subtle border border-success-subtle rounded-2 align-items-center",
              );
              logo.setAttribute("class", "fas fa-check m-2");
              span.setAttribute("class", "text-success");
              span.textContent = "Completed";
            } else {
              div.setAttribute(
                "class",
                "d-flex fw-semibold text-white-emphasis bg-white-subtle border border-white-subtle rounded-2 align-items-center",
              );
              span.setAttribute("class", "text-muted");
              logo.setAttribute("class", "fas fa-percentage m-2");
            }
            div.appendChild(logo);
            div.appendChild(span);
            return div.outerHTML;
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
    evidences.searchBuilder
      .container()
      .prependTo($(evidences.table().container()));
  });
}

function display_evidence(evidence_id) {
  $(".modal_evidence_review").modal("show");
  $.ajax({
    type: "GET",
    url: "/api/evidences/" + evidence_id + "/",
    dataType: "json",
    success: function (evidence_data) {
      $(".modal_evidence_review").attr("id", evidence_data.dump_id);
      $(".modal_evidence_review").attr("value", evidence_data.dump_os);
      $(".evidence_etag").text(evidence_data.dump_etag);
      $(".evidence_name").text(evidence_data.dump_name);
      $(".evidence_os").text(evidence_data.dump_os);
      $(".evidence_status").text(evidence_data.dump_status);

      var logsList = document.createElement("div");
      logsList.className = "row";
      var leftColList = document.createElement("ul");
      leftColList.className = "list-group list-group-flush col-4";
      var middleColList = document.createElement("ul");
      middleColList.className = "list-group list-group-flush col-4";
      var rightColList = document.createElement("ul");
      rightColList.className = "list-group list-group-flush col-4";
      var count = 0;
      for (var key in evidence_data.dump_logs) {
        var listItem = document.createElement("li");
        listItem.className = "list-group-item";
        var small = document.createElement("small");
        if (evidence_data.dump_logs[key] == "Success") {
          small.classList.add("text-success");
        } else {
          small.classList.add("text-danger");
        }
        small.textContent = evidence_data.dump_logs[key];
        small_key = document.createElement("small");
        small_key.textContent = key + ": ";
        small_key.appendChild(small);
        listItem.appendChild(small_key);
        if (count % 3 === 0) {
          leftColList.appendChild(listItem);
        } else if (count % 3 === 1) {
          middleColList.appendChild(listItem);
        } else {
          rightColList.appendChild(listItem);
        }
        count++;
      }
      logsList.appendChild(leftColList);
      logsList.appendChild(middleColList);
      logsList.appendChild(rightColList);
      document.querySelector(".evidence_logs").innerHTML = "";
      document.querySelector(".evidence_logs").appendChild(logsList);

      $(".evidence_info").removeClass("placeholder");
    },
    error: function (xhr, status, error) {
      toastr.error(
        "An error occurred: " +
          error +
          ", Make sure you CORS authorizations are correct if you are using AWS.",
      );
    },
  });
}

function create_evidence(filename, etag) {
  var formData = {
    dump_name: filename,
    dump_etag: etag,
    dump_os: $("#id_dump_os").val(),
    dump_linked_case: $("#id_dump_linked_case").val(),
  };
  $.ajaxSetup({
    beforeSend: function (xhr, settings) {
      xhr.setRequestHeader(
        "X-CSRFToken",
        document.querySelector("[name=csrfmiddlewaretoken]").value,
      );
    },
  });
  $.ajax({
    type: "POST",
    url: "/api/evidences/",
    data: formData,
    dataType: "json",
    success: function (response) {
      toastr.success("Evidence created.");
    },
    error: function (xhr, status, error) {
      if (xhr.status == 409) {
        toastr.warning("Evidence with this ETag already exists.");
      } else {
        toastr.error("An error occurred : " + error);
      }
    },
  });
}

function delete_evidence(dump_id) {
  $.ajaxSetup({
    beforeSend: function (xhr, settings) {
      xhr.setRequestHeader(
        "X-CSRFToken",
        document.querySelector("[name=csrfmiddlewaretoken]").value,
      );
    },
  });
  $.ajax({
    type: "DELETE",
    url: "/api/evidences/" + dump_id + "/",
    dataType: "json",
    success: function (data) {
      $(".modal_evidence_review").attr("id", NaN);
      $(".modal_evidence_review").attr("value", NaN);
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
      if (xhr.responseText) {
        toastr.error(xhr.responseText);
      }
    },
  });
}

function start_analysis(dump_id, case_id) {
  $.ajaxSetup({
    beforeSend: function (xhr, settings) {
      xhr.setRequestHeader(
        "X-CSRFToken",
        document.querySelector("[name=csrfmiddlewaretoken]").value,
      );
    },
  });
  $.ajax({
    type: "POST",
    url: "/api/evidences/launch_task/",
    data: JSON.stringify({ dump_id: dump_id }),
    contentType: "application/json",
    dataType: "json",
    success: function (data) {
      toastr.success("Analysis launched.");
      get_evidences(case_id);
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred while launching the analysis: " + error);
    },
  });
}

function clear_form() {
  $(":input", "#evidence_form")
    .not(":button, :submit, :reset, :hidden")
    .val("")
    .prop("checked", false)
    .prop("selected", false);
}

function reconnectWebSocket() {
  toastr.info("Trying to reconnect in " + reconnectDelay / 1000 + "seconds");
  setTimeout(function () {
    connectWebSocket();
    reconnectDelay *= 2;
  }, reconnectDelay);
}

function connectWebSocket(case_id) {
  $.ajax({
    url: "/websocket-url/",
    type: "GET",
    dataType: "json",
    success: function (data) {
      var websocketUrl = `${data.websocket_url}/ws/evidences/`;
      const socket_evidences = new WebSocket(websocketUrl);

      socket_evidences.onopen = function () {
        reconnectDelay = 5000;
        get_evidences(case_id);
      };

      socket_evidences.onmessage = function (e) {
        result = JSON.parse(e.data);

        if (result.status === "created") {
          if (case_id) {
            if (result.message.dump_linked_case == case_id) {
              try {
                evidences
                  .row("#" + result.message.dump_id)
                  .data(result.message);
              } catch {
                evidences.row.add(result.message).draw().node();
              }
              if (result.message.dump_status === 100) {
                $("#" + result.message.dump_id).removeClass("not-completed");
                $("#" + result.message.dump_id).addClass("completed");
              } else {
                $("#" + result.message.dump_id).removeClass("completed");
                $("#" + result.message.dump_id).addClass("not-completed");
              }
            }
          } else {
            try {
              evidences.row("#" + result.message.dump_id).data(result.message);
            } catch {
              evidences.row.add(result.message).draw().node();
            }
            if (result.message.dump_status === 100) {
              $("#" + result.message.dump_id).removeClass("not-completed");
              $("#" + result.message.dump_id).addClass("completed");
            } else {
              $("#" + result.message.dump_id).removeClass("completed");
              $("#" + result.message.dump_id).addClass("not-completed");
            }
          }
        }

        if (result.status === "deleted") {
          if (case_id) {
            if (result.message.dump_linked_case == case_id) {
              try {
                evidences
                  .row("#" + result.message.dump_id)
                  .remove()
                  .draw();
              } catch {
                toastr.error("Could not delete the evidence.");
              }
            }
          } else {
            try {
              evidences
                .row("#" + result.message.dump_id)
                .remove()
                .draw();
            } catch {
              toastr.error("Could not delete the evidence.");
            }
          }
        }
      };

      socket_evidences.onclose = function () {
        toastr.warning("Synchronization lost.");
        try {
          evidences.rows().remove().draw();
        } catch {}
        reconnectWebSocket();
      };

      socket_evidences.onerror = function (error) {
        toastr.error("Can't connect to the server.", error);
        socket_evidences.close();
      };
      $("#loading-content").addClass("d-none");
      $("#main-content").removeClass("d-none");
    },
    error: function (xhr, status, error) {
      reconnectWebSocket();
      console.log("Error fetching WebSocket URL:", xhr.responseText);
    },
  });
}
