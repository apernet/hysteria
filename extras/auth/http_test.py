from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/auth", methods=["POST"])
def auth():
    data = request.json

    if data is None:
        return jsonify({"ok": False, "id": ""}), 400

    addr = data.get("addr", "")
    auth = data.get("auth", "")
    tx = data.get("tx", 0)

    if addr == "123.123.123.123:5566" and auth == "wahaha" and tx == 12345:
        return jsonify({"ok": True, "id": "some_unique_id"})
    else:
        return jsonify({"ok": False, "id": ""})


if __name__ == "__main__":
    app.run()
