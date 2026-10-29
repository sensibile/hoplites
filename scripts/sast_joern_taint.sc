// Source-to-sink taint flows for a Python CPG, driven by a hoplites Joern model JSON.
// Output: {"flows": [{rule, cwe, source, sink, path: [{file, line, code}]}]}

@main def exec(cpgFile: String, modelFile: String, outFile: String) = {
  importCpg(cpgFile)
  val model = ujson.read(os.read(os.Path(modelFile)))
  val sourceRe = model("sources").arr.map(_.str).mkString("|")
  val sanitizerRe = model("sanitizers").arr.map(_.str).toList
  def sources = cpg.call.code(sourceRe)
  def sanitized(path: io.joern.dataflowengineoss.language.Path): Boolean =
    sanitizerRe.nonEmpty && path.elements.exists {
      case c: io.shiftleft.codepropertygraph.generated.nodes.Call => sanitizerRe.exists(re => c.code.matches(re))
      case _ => false
    }
  val flows = model("sinks").arr.toList.flatMap { s =>
    val codeRe = s.obj.get("code").map(_.str)
    val sinkCalls = cpg.call.name(s("name").str).l.filter(c => codeRe.forall(re => c.code.matches(re)))
    val args = sinkCalls.flatMap(_.argument.l.filter(_.argumentIndex >= 1))
    args.reachableByFlows(sources).l.filterNot(sanitized).map { path =>
      val steps = path.elements.map { e =>
        ujson.Obj(
          "file" -> e.location.filename,
          "line" -> e.lineNumber.map(n => ujson.Num(n.toDouble)).getOrElse(ujson.Null),
          "code" -> e.code.take(200)
        )
      }
      ujson.Obj(
        "rule" -> s("id").str,
        "cwe" -> s("cwe").str,
        "source" -> path.elements.head.code.take(200),
        "sink" -> path.elements.last.code.take(200),
        "path" -> ujson.Arr(steps*)
      )
    }
  }
  val distinct = flows.distinctBy(f => (f("rule").str, f("path").arr.map(p => (p("file").toString, p("line").toString)).toList))
  os.write.over(os.Path(outFile), ujson.write(ujson.Obj("model" -> model("id").str, "flows" -> ujson.Arr(distinct*)), indent = 2))
}
